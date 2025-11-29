mod common;
mod config;
mod proxy;

use crate::config::Config;
use crate::proxy::*;

use std::collections::HashMap;
use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use serde_json::json;
use uuid::Uuid;
use worker::*;
use once_cell::sync::Lazy;
use regex::Regex;

static PROXYIP_PATTERN: Lazy<Regex> = Lazy::new(|| Regex::new(r"^.+-\d+$").unwrap());
static PROXYKV_PATTERN: Lazy<Regex> = Lazy::new(|| Regex::new(r"^([A-Z]{2})").unwrap());

#[event(fetch)]
async fn main(req: Request, env: Env, _: Context) -> Result<Response> {
    let uuid = env
        .var("UUID")
        .map(|x| Uuid::parse_str(&x.to_string()).unwrap_or_default())?;
    let host = req.url()?.host().map(|x| x.to_string()).unwrap_or_default();
    let main_page_url = env.var("MAIN_PAGE_URL").map(|x|x.to_string()).unwrap();
    let sub_page_url = env.var("SUB_PAGE_URL").map(|x|x.to_string()).unwrap();
    let config = Config { uuid, host: host.clone(), proxy_addr: host, proxy_port: 443, main_page_url, sub_page_url };

    Router::with_data(config)
        .on_async("/", fe)
        .on_async("/sub", sub)
        .on("/link", link)
        // existing generic route that handles /:proxyip (e.g. /ID, /KR, /US, or ip-port-like)
        .on_async("/:proxyip", tunnel)
        // explicit aliases for protocols (will be handled by same tunnel handler)
        .on_async("/vmess", tunnel)
        .on_async("/vless", tunnel)
        .on_async("/trojan", tunnel)
        .on_async("/shadowsocks", tunnel)
        .run(req, env)
        .await
}

async fn get_response_from_url(url: String) -> Result<Response> {
    let req = Fetch::Url(Url::parse(url.as_str())?);
    let mut res = req.send().await?;
    Response::from_html(res.text().await?)
}

async fn fe(_: Request, cx: RouteContext<Config>) -> Result<Response> {
    get_response_from_url(cx.data.main_page_url).await
}

async fn sub(_: Request, cx: RouteContext<Config>) -> Result<Response> {
    get_response_from_url(cx.data.sub_page_url).await
}


async fn tunnel(req: Request, mut cx: RouteContext<Config>) -> Result<Response> {
    // ambil param path (bisa /ID, /vmess, /vless, /trojan, atau ip-PORT)
    let mut proxyip = cx.param("proxyip").cloned().unwrap_or_default();

    // default protocol label
    let mut protocol = String::new();

    // Jika route dipanggil via /vmess, /vless, /trojan (alias tanpa param),
    // cx.param("proxyip") bisa kosong, jadi cek juga path dari request URL
    if proxyip.is_empty() {
        if let Ok(url) = req.url() {
            if let Some(path) = url.path_segments().and_then(|mut it| it.next()) {
                proxyip = path.to_string();
            }
        }
    }

    // Normalize lower/upper for matching aliases
    let proxyip_lower = proxyip.to_lowercase();

    // Map alias routes to the country code you want (di sini map semua alias -> "ID")
    // Ubah "ID" jadi country/KV key lain sesuai akun masing-masing jika diperlukan.
    match proxyip_lower.as_str() {
        "vmess" => {
            protocol = "vmess".to_string();
            proxyip = "AM".to_string(); // map vmess -> use KV key "ID"
        }
        "vless" => {
            protocol = "vless".to_string();
            proxyip = "AM".to_string(); // map vless -> use KV key "ID"
        }
        "trojan" => {
            protocol = "trojan".to_string();
            proxyip = "AM".to_string(); // map trojan -> use KV key "ID"
        }
        "shadowsocks" => {
            protocol = "shadowsocks".to_string();
            proxyip = "AM".to_string();
        }
        _ => {
            // jika bukan alias, tetap gunakan apa yang diberikan di path
        }
    }

    // Kalau proxyip cocok pola 2 huruf (country code), ambil dari KV
    if PROXYKV_PATTERN.is_match(&proxyip)  {
        // kvid_list dukung format "ID,KR" jika mau acak antar beberapa key
        let kvid_list: Vec<String> = proxyip.split(",").map(|s|s.to_string()).collect();
        let kv = cx.kv("SIREN")?;
        let mut proxy_kv_str = kv.get("proxy_kv").text().await?.unwrap_or("".to_string());
        let mut rand_buf = [0u8, 1];
        getrandom::getrandom(&mut rand_buf).expect("failed generating random number");
        
        if proxy_kv_str.len() == 0 {
            console_log!("getting proxy kv from github...");
            let req = Fetch::Url(Url::parse("https://raw.githubusercontent.com/FoolVPN-ID/Nautica/refs/heads/main/kvProxyList.json")?);
            let mut res = req.send().await?;
            if res.status_code() == 200 {
                proxy_kv_str = res.text().await?.to_string();
                kv.put("proxy_kv", &proxy_kv_str)?.expiration_ttl(60 * 60 * 24).execute().await?; // 24 hours
            } else {
                return Err(Error::from(format!("error getting proxy kv: {}", res.status_code())));
            }
        }
        
        let proxy_kv: HashMap<String, Vec<String>> = serde_json::from_str(&proxy_kv_str)?;
        
        // select random KV ID
        let kv_index = (rand_buf[0] as usize) % kvid_list.len();
        proxyip = kvid_list[kv_index].clone();
        
        // select random proxy ip from that KV list
        let proxyip_index = (rand_buf[0] as usize) % proxy_kv[&proxyip].len();
        proxyip = proxy_kv[&proxyip][proxyip_index].clone().replace(":", "-");
    }

    // lanjutkan seperti sebelumnya: kalau websocket dan proxyip cocok pola ip-port
    let upgrade = req.headers().get("Upgrade")?.unwrap_or_default();
    if upgrade == "websocket".to_string() && PROXYIP_PATTERN.is_match(&proxyip) {
        if let Some((addr, port_str)) = proxyip.split_once('-') {
            if let Ok(port) = port_str.parse() {
                cx.data.proxy_addr = addr.to_string();
                cx.data.proxy_port = port;
            }
        }
        
        // NOTE: saat ini `protocol` hanya disimpan lokal; jika nanti kamu mau menyesuaikan path/ws headers
        // berdasarkan protocol (mis. ganti path pada VMESS vs VLESS), kamu bisa menggunakan variable `protocol`
        // di sini untuk mengubah perilaku (mis. set subprotocols, path, dsb).

        let WebSocketPair { server, client } = WebSocketPair::new()?;
        server.accept()?;
    
        wasm_bindgen_futures::spawn_local(async move {
            let events = server.events().unwrap();
            if let Err(e) = ProxyStream::new(cx.data, &server, events).process().await {
                console_error!("[tunnel]: {}", e);
            }
        });
    
        Response::from_websocket(client)
    } else {
        Response::from_html("hi from wasm!")
    }

}

fn link(_: Request, cx: RouteContext<Config>) -> Result<Response> {
    let host = cx.data.host.to_string();
    let uuid = cx.data.uuid.to_string();

    let vmess_link = {
        let config = json!({
            "ps": "siren vmess",
            "v": "2",
            "add": host,
            "port": "80",
            "id": uuid,
            "aid": "0",
            "scy": "zero",
            "net": "ws",
            "type": "none",
            "host": host,
            "path": "/KR",
            "tls": "",
            "sni": "",
            "alpn": ""}
        );
        format!("vmess://{}", URL_SAFE.encode(config.to_string()))
    };
    let vless_link = format!("vless://{uuid}@{host}:443?encryption=none&type=ws&host={host}&path=%2FKR&security=tls&sni={host}#siren vless");
    let trojan_link = format!("trojan://{uuid}@{host}:443?encryption=none&type=ws&host={host}&path=%2FKR&security=tls&sni={host}#siren trojan");
    let ss_link = format!("ss://{}@{host}:443?plugin=v2ray-plugin%3Btls%3Bmux%3D0%3Bmode%3Dwebsocket%3Bpath%3D%2FKR%3Bhost%3D{host}#siren ss", URL_SAFE.encode(format!("none:{uuid}")));
    
    Response::from_body(ResponseBody::Body(format!("{vmess_link}\n{vless_link}\n{trojan_link}\n{ss_link}").into()))
}
