use std::{
    cell::Cell,
    collections::HashMap,
    io::{Read, Write},
    net::{Ipv4Addr, Ipv6Addr, Shutdown, SocketAddrV4, TcpListener, TcpStream},
    sync::{Mutex, OnceLock},
    thread,
    time::Duration,
};

use anyhow::Result;
use ilhook::x64::Registers;
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6, SOCKADDR_IN, SOCKADDR_IN6};

use super::{network::is_official_sdk_host, MhyContext, MhyModule, ModuleType};

pub struct Socket;

static TLS_RELAY_PORTS: OnceLock<Mutex<HashMap<Ipv4Addr, u16>>> = OnceLock::new();
static PROXY_RELAY_PORTS: OnceLock<Mutex<HashMap<SocketAddrV4, u16>>> = OnceLock::new();

thread_local! {
    static BYPASS_CONNECT_HOOK: Cell<bool> = const { Cell::new(false) };
}

const OFFICIAL_GAME_IP: Ipv4Addr = Ipv4Addr::new(43, 163, 62, 120);
const OFFICIAL_GAME_PORT: u16 = 443;
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

impl MhyModule for MhyContext<Socket> {
    unsafe fn init(&mut self) -> Result<()> {
        let config = crate::config::get().map_err(anyhow::Error::msg)?;
        let target_ip = config
            .game
            .ipv4
            .ok_or_else(|| anyhow::anyhow!("game.ipv4 is required"))?;
        let tls_ip = config
            .tls
            .ipv4
            .ok_or_else(|| anyhow::anyhow!("tls.ipv4 is required"))?;
        TLS_RELAY_PORTS
            .set(Mutex::new(HashMap::new()))
            .map_err(|_| anyhow::anyhow!("TLS relay registry was already initialized"))?;
        PROXY_RELAY_PORTS
            .set(Mutex::new(HashMap::new()))
            .map_err(|_| anyhow::anyhow!("proxy relay registry was already initialized"))?;
        relay_port_for(
            OFFICIAL_GAME_IP,
            target_ip,
            config.game.port,
            tls_ip,
            config.tls.port,
            &config.tls.host,
        )?;
        let addr = self.get_export("Ws2_32.dll", "connect")?;
        self.interceptor.attach(addr, on_connect)?;
        let wsa_connect = self.get_export("Ws2_32.dll", "WSAConnect")?;
        self.interceptor.attach(wsa_connect, on_connect)?;
        crate::diagnostics::event("socket hooks attached to connect and WSAConnect");
        Ok(())
    }

    unsafe fn de_init(&mut self) -> Result<()> {
        Ok(())
    }

    fn get_module_type(&self) -> ModuleType {
        ModuleType::Socket
    }
}

unsafe extern "win64" fn on_connect(reg: *mut Registers, _: usize) {
    if BYPASS_CONNECT_HOOK.get() {
        return;
    }

    let sockaddr_ptr = (*reg).rdx as *mut SOCKADDR_IN;

    if sockaddr_ptr.is_null() {
        return;
    }

    let family = (*sockaddr_ptr).sin_family;
    if family.0 == AF_INET6.0 {
        on_connect_ipv6((*reg).rdx as *mut SOCKADDR_IN6);
        return;
    }
    if family.0 != AF_INET.0 {
        return;
    }

    let sockaddr = &mut *sockaddr_ptr;

    let ip = Ipv4Addr::from(u32::from_be(sockaddr.sin_addr.S_un.S_addr));
    let port = u16::from_be(sockaddr.sin_port);

    let key = format!("{ip}:{port}");
    println!("[connect] IP: {ip}, Port: {port}");

    if port == 443 {
        crate::diagnostics::event(&format!("tls connect candidate source={key} family=ipv4"));
    }

    let Ok(config) = crate::config::get() else {
        return;
    };

    if is_configured_proxy_endpoint(config.proxy.as_ref(), ip, port)
        && !is_internal_relay_port(port)
    {
        let Some(tls_ip) = config.tls.ipv4 else {
            crate::diagnostics::event("proxy relay unavailable; tls.ipv4 is missing");
            return;
        };
        let origin = SocketAddrV4::new(ip, port);
        match proxy_relay_port_for(origin, tls_ip, config.tls.port, &config.tls.host) {
            Ok(local_port) => {
                crate::diagnostics::event(&format!(
                    "loopback proxy relay source={origin} target=127.0.0.1:{local_port}"
                ));
                sockaddr.sin_port = local_port.to_be();
            }
            Err(error) => crate::diagnostics::event(&format!(
                "loopback proxy relay creation failed for {origin}: {error:#}"
            )),
        }
        return;
    }

    if port == 443 && config.tls.ipv4 == Some(ip) {
        crate::diagnostics::event(&format!(
            "sdk tls redirect source={key} target={ip}:{}",
            config.tls.port
        ));
        sockaddr.sin_port = config.tls.port.to_be();
        return;
    }

    if port == OFFICIAL_GAME_PORT && !ip.is_loopback() {
        let (Some(game_ip), Some(tls_ip)) = (config.game.ipv4, config.tls.ipv4) else {
            crate::diagnostics::event(
                "protocol relay unavailable; game.ipv4 or tls.ipv4 is missing",
            );
            return;
        };
        match relay_port_for(
            ip,
            game_ip,
            config.game.port,
            tls_ip,
            config.tls.port,
            &config.tls.host,
        ) {
            Ok(local_port) => {
                crate::diagnostics::event(&format!(
                    "protocol relay source={key} target=127.0.0.1:{local_port} family=ipv4"
                ));
                sockaddr.sin_addr.S_un.S_addr = u32::from(Ipv4Addr::LOCALHOST).to_be();
                sockaddr.sin_port = local_port.to_be();
            }
            Err(error) => crate::diagnostics::event(&format!(
                "protocol relay creation failed for {key}: {error:#}"
            )),
        }
    }
}

unsafe fn on_connect_ipv6(sockaddr_ptr: *mut SOCKADDR_IN6) {
    if sockaddr_ptr.is_null() {
        return;
    }
    let sockaddr = &mut *sockaddr_ptr;
    let bytes = sockaddr.sin6_addr.u.Byte;
    let ip = Ipv6Addr::from(bytes);
    let port = u16::from_be(sockaddr.sin6_port);
    let mapped = mapped_ipv4(bytes);

    if port == 443 {
        crate::diagnostics::event(&format!(
            "tls connect candidate source=[{ip}]:{port} family=ipv6 mapped_ipv4={}",
            mapped
                .map(|value| value.to_string())
                .unwrap_or_else(|| "none".to_string())
        ));
    }

    let Some(ipv4) = mapped else {
        return;
    };
    let Ok(config) = crate::config::get() else {
        return;
    };

    if is_configured_proxy_endpoint(config.proxy.as_ref(), ipv4, port)
        && !is_internal_relay_port(port)
    {
        let Some(tls_ip) = config.tls.ipv4 else {
            crate::diagnostics::event("proxy relay unavailable; tls.ipv4 is missing");
            return;
        };
        let origin = SocketAddrV4::new(ipv4, port);
        match proxy_relay_port_for(origin, tls_ip, config.tls.port, &config.tls.host) {
            Ok(local_port) => {
                crate::diagnostics::event(&format!(
                    "loopback proxy relay source=[{ip}]:{port} target=127.0.0.1:{local_port} family=ipv6-mapped"
                ));
                sockaddr.sin6_addr.u.Byte = ipv4_mapped_bytes(Ipv4Addr::LOCALHOST);
                sockaddr.sin6_port = local_port.to_be();
            }
            Err(error) => crate::diagnostics::event(&format!(
                "loopback proxy relay creation failed for [{ip}]:{port}: {error:#}"
            )),
        }
        return;
    }

    if port == 443 && config.tls.ipv4 == Some(ipv4) {
        crate::diagnostics::event(&format!(
            "sdk tls redirect source=[{ip}]:{port} target={ipv4}:{} family=ipv6-mapped",
            config.tls.port
        ));
        sockaddr.sin6_port = config.tls.port.to_be();
        return;
    }

    if port == OFFICIAL_GAME_PORT && !ipv4.is_loopback() {
        let (Some(game_ip), Some(tls_ip)) = (config.game.ipv4, config.tls.ipv4) else {
            crate::diagnostics::event(
                "protocol relay unavailable; game.ipv4 or tls.ipv4 is missing",
            );
            return;
        };
        match relay_port_for(
            ipv4,
            game_ip,
            config.game.port,
            tls_ip,
            config.tls.port,
            &config.tls.host,
        ) {
            Ok(local_port) => {
                crate::diagnostics::event(&format!(
                    "protocol relay source=[{ip}]:{port} target=127.0.0.1:{local_port} family=ipv6-mapped"
                ));
                sockaddr.sin6_addr.u.Byte = ipv4_mapped_bytes(Ipv4Addr::LOCALHOST);
                sockaddr.sin6_port = local_port.to_be();
            }
            Err(error) => crate::diagnostics::event(&format!(
                "protocol relay creation failed for [{ip}]:{port}: {error:#}"
            )),
        }
    }
}

fn mapped_ipv4(bytes: [u8; 16]) -> Option<Ipv4Addr> {
    (bytes[..10] == [0; 10] && bytes[10..12] == [0xff, 0xff])
        .then(|| Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]))
}

fn ipv4_mapped_bytes(ip: Ipv4Addr) -> [u8; 16] {
    let mut bytes = [0; 16];
    bytes[10] = 0xff;
    bytes[11] = 0xff;
    bytes[12..].copy_from_slice(&ip.octets());
    bytes
}

fn is_configured_proxy_endpoint(
    proxy: Option<&crate::config::ProxyEndpoint>,
    ip: Ipv4Addr,
    port: u16,
) -> bool {
    proxy.is_some_and(|proxy| proxy.ipv4 == ip && proxy.port == port)
}

fn is_internal_relay_port(port: u16) -> bool {
    let tls_relay = TLS_RELAY_PORTS
        .get()
        .and_then(|relays| relays.lock().ok())
        .is_some_and(|relays| relays.values().any(|value| *value == port));
    let proxy_relay = PROXY_RELAY_PORTS
        .get()
        .and_then(|relays| relays.lock().ok())
        .is_some_and(|relays| relays.values().any(|value| *value == port));
    tls_relay || proxy_relay
}

fn proxy_relay_port_for(
    origin: SocketAddrV4,
    tls_ip: Ipv4Addr,
    tls_port: u16,
    tls_host: &str,
) -> Result<u16> {
    let relays = PROXY_RELAY_PORTS
        .get()
        .ok_or_else(|| anyhow::anyhow!("proxy relay registry is not initialized"))?;
    let mut relays = relays
        .lock()
        .map_err(|_| anyhow::anyhow!("proxy relay registry lock is poisoned"))?;
    if let Some(port) = relays.get(&origin).copied() {
        return Ok(port);
    }

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let local_port = listener.local_addr()?.port();
    relays.insert(origin, local_port);
    let tls_host = tls_host.to_string();

    thread::Builder::new()
        .name(format!("sonetto-proxy-relay-{}", origin.port()))
        .spawn(move || {
            crate::diagnostics::event(&format!(
                "loopback proxy relay listening on 127.0.0.1:{local_port} origin={origin}"
            ));
            for incoming in listener.incoming() {
                match incoming {
                    Ok(client) => {
                        let tls_host = tls_host.clone();
                        thread::spawn(move || {
                            if let Err(error) = route_proxy_connection(
                                client, origin, tls_ip, tls_port, &tls_host,
                            ) {
                                crate::diagnostics::event(&format!(
                                    "loopback proxy relay connection failed origin={origin}: {error:#}"
                                ));
                            }
                        });
                    }
                    Err(error) => crate::diagnostics::event(&format!(
                        "loopback proxy relay accept failed origin={origin}: {error}"
                    )),
                }
            }
        })?;

    Ok(local_port)
}

fn route_proxy_connection(
    mut client: TcpStream,
    proxy_origin: SocketAddrV4,
    tls_ip: Ipv4Addr,
    tls_port: u16,
    tls_host: &str,
) -> Result<()> {
    client.set_read_timeout(Some(PROBE_TIMEOUT))?;
    let mut prefix = [0_u8; 8];
    let prefix_len = read_initial_prefix(&mut client, &mut prefix)?;
    let mut request = prefix[..prefix_len].to_vec();

    if request.eq_ignore_ascii_case(b"CONNECT ") {
        while request.len() < 16 * 1024 && !request.windows(4).any(|part| part == b"\r\n\r\n") {
            let mut chunk = [0_u8; 1024];
            let count = client.read(&mut chunk)?;
            if count == 0 {
                break;
            }
            request.extend_from_slice(&chunk[..count]);
        }
        if let Some(host) = parse_connect_host(&request) {
            if is_official_sdk_host(&host) {
                crate::diagnostics::event(&format!(
                    "SDK HTTP CONNECT intercepted host={host} proxy={proxy_origin} target={tls_ip}:{tls_port}"
                ));
                client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
                client.flush()?;
                client.set_read_timeout(None)?;
                return route_private_tls_connection(client, tls_ip, tls_port, tls_host);
            }
        }
    }
    client.set_read_timeout(None)?;

    crate::diagnostics::event(&format!(
        "loopback proxy passthrough origin={proxy_origin} prefix={}",
        hex_prefix(&request[..request.len().min(8)])
    ));
    let mut upstream = connect_without_hook(proxy_origin)?;
    upstream.write_all(&request)?;
    relay_streams(client, upstream)
}

fn parse_connect_host(request: &[u8]) -> Option<String> {
    let line_end = request.windows(2).position(|part| part == b"\r\n")?;
    let line = std::str::from_utf8(&request[..line_end]).ok()?;
    let mut parts = line.split_ascii_whitespace();
    if !parts.next()?.eq_ignore_ascii_case("CONNECT") {
        return None;
    }
    let authority = parts.next()?;
    let host = authority
        .strip_prefix('[')
        .and_then(|value| value.split_once(']').map(|(host, _)| host))
        .or_else(|| authority.rsplit_once(':').map(|(host, _)| host))
        .unwrap_or(authority);
    Some(host.to_string())
}

fn route_private_tls_connection(
    mut client: TcpStream,
    tls_ip: Ipv4Addr,
    tls_port: u16,
    tls_host: &str,
) -> Result<()> {
    client.set_read_timeout(Some(PROBE_TIMEOUT))?;
    let mut prefix = [0_u8; 5];
    let prefix_len = read_initial_prefix(&mut client, &mut prefix)?;
    if !is_tls_client_hello(&prefix[..prefix_len]) {
        return Err(anyhow::anyhow!(
            "HTTP CONNECT tunnel did not start with TLS ClientHello"
        ));
    }
    let record_len = u16::from_be_bytes([prefix[3], prefix[4]]) as usize;
    if record_len == 0 || record_len > 16 * 1024 {
        return Err(anyhow::anyhow!("HTTP CONNECT TLS record length is invalid"));
    }
    let mut record = prefix.to_vec();
    record.resize(5 + record_len, 0);
    client.read_exact(&mut record[5..])?;
    client.set_read_timeout(None)?;
    rewrite_tls_sni(&mut record, tls_host)?;

    let target = SocketAddrV4::new(tls_ip, tls_port);
    let mut upstream = connect_without_hook(target)?;
    upstream.write_all(&record)?;
    relay_streams(client, upstream)
}

fn relay_port_for(
    origin_ip: Ipv4Addr,
    game_ip: Ipv4Addr,
    game_port: u16,
    tls_ip: Ipv4Addr,
    tls_port: u16,
    tls_host: &str,
) -> Result<u16> {
    let relays = TLS_RELAY_PORTS
        .get()
        .ok_or_else(|| anyhow::anyhow!("TLS relay registry is not initialized"))?;
    let mut relays = relays
        .lock()
        .map_err(|_| anyhow::anyhow!("TLS relay registry lock is poisoned"))?;
    if let Some(port) = relays.get(&origin_ip).copied() {
        return Ok(port);
    }

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let local_port = listener.local_addr()?.port();
    relays.insert(origin_ip, local_port);
    let tls_host = tls_host.to_string();

    thread::Builder::new()
        .name(format!("sonetto-relay-{origin_ip}"))
        .spawn(move || {
            crate::diagnostics::event(&format!(
                "protocol relay listening on 127.0.0.1:{local_port} origin={origin_ip}:443"
            ));
            for incoming in listener.incoming() {
                match incoming {
                    Ok(client) => {
                        let tls_host = tls_host.clone();
                        thread::spawn(move || {
                            if let Err(error) = route_connection(
                                client, origin_ip, game_ip, game_port, tls_ip, tls_port, &tls_host,
                            ) {
                                crate::diagnostics::event(&format!(
                                    "protocol relay connection failed origin={origin_ip}: {error:#}"
                                ));
                            }
                        });
                    }
                    Err(error) => crate::diagnostics::event(&format!(
                        "protocol relay accept failed origin={origin_ip}: {error}"
                    )),
                }
            }
        })?;

    Ok(local_port)
}

fn route_connection(
    mut client: TcpStream,
    origin_ip: Ipv4Addr,
    game_ip: Ipv4Addr,
    game_port: u16,
    tls_ip: Ipv4Addr,
    tls_port: u16,
    tls_host: &str,
) -> Result<()> {
    client.set_read_timeout(Some(PROBE_TIMEOUT))?;
    let mut prefix = [0_u8; 5];
    let prefix_len = read_initial_prefix(&mut client, &mut prefix)?;
    client.set_read_timeout(None)?;

    let mut initial = prefix[..prefix_len].to_vec();
    let (target, route, payload) = if is_tls_client_hello(&initial) {
        let record_len = u16::from_be_bytes([initial[3], initial[4]]) as usize;
        if record_len == 0 || record_len > 16 * 1024 {
            (
                SocketAddrV4::new(origin_ip, OFFICIAL_GAME_PORT),
                "official tls passthrough (invalid record)",
                initial,
            )
        } else {
            initial.resize(5 + record_len, 0);
            client.read_exact(&mut initial[5..])?;
            if should_route_tls_to_private(&initial) {
                rewrite_tls_sni(&mut initial, tls_host)?;
                (
                    SocketAddrV4::new(tls_ip, tls_port),
                    "private tls redirect",
                    initial,
                )
            } else {
                (
                    SocketAddrV4::new(origin_ip, OFFICIAL_GAME_PORT),
                    "official tls passthrough",
                    initial,
                )
            }
        }
    } else if origin_ip == OFFICIAL_GAME_IP {
        (
            SocketAddrV4::new(game_ip, game_port),
            "game redirect",
            initial,
        )
    } else {
        (
            SocketAddrV4::new(origin_ip, OFFICIAL_GAME_PORT),
            "non-tls passthrough",
            initial,
        )
    };

    crate::diagnostics::event(&format!(
        "protocol relay {route} origin={origin_ip}:443 prefix={} target={target}",
        hex_prefix(&payload[..payload.len().min(5)])
    ));

    let mut upstream = connect_without_hook(target)?;
    upstream.write_all(&payload)?;

    relay_streams(client, upstream)
}

fn relay_streams(mut client: TcpStream, mut upstream: TcpStream) -> Result<()> {
    let mut client_reader = client.try_clone()?;
    let mut upstream_writer = upstream.try_clone()?;
    let upload = thread::spawn(move || {
        let result = std::io::copy(&mut client_reader, &mut upstream_writer);
        let _ = upstream_writer.shutdown(Shutdown::Write);
        result
    });

    std::io::copy(&mut upstream, &mut client)?;
    let _ = client.shutdown(Shutdown::Write);
    let _ = upload.join();
    Ok(())
}

fn extract_tls_sni(record: &[u8]) -> Option<String> {
    if record.len() < 5 || !is_tls_client_hello(record) || record[5] != 1 {
        return None;
    }
    let handshake_len = u32::from_be_bytes([0, record[6], record[7], record[8]]) as usize;
    let body_start: usize = 9;
    let body_end = body_start.checked_add(handshake_len)?;
    if body_end > record.len() || handshake_len < 34 {
        return None;
    }
    let mut cursor: usize = body_start + 34;
    cursor = cursor.checked_add(1 + *record.get(cursor)? as usize)?;
    cursor = cursor.checked_add(
        2 + u16::from_be_bytes([*record.get(cursor)?, *record.get(cursor + 1)?]) as usize,
    )?;
    cursor = cursor.checked_add(1 + *record.get(cursor)? as usize)?;
    let extensions_len =
        u16::from_be_bytes([*record.get(cursor)?, *record.get(cursor + 1)?]) as usize;
    let mut pos = cursor + 2;
    let extensions_end = pos.checked_add(extensions_len)?;
    if extensions_end > body_end {
        return None;
    }
    while pos + 4 <= extensions_end {
        let extension_type = u16::from_be_bytes([record[pos], record[pos + 1]]);
        let extension_len = u16::from_be_bytes([record[pos + 2], record[pos + 3]]) as usize;
        let data_start = pos + 4;
        let data_end = data_start.checked_add(extension_len)?;
        if data_end > extensions_end {
            return None;
        }
        if extension_type == 0 && extension_len >= 5 {
            let name_type = record[data_start + 2];
            let name_len =
                u16::from_be_bytes([record[data_start + 3], record[data_start + 4]]) as usize;
            let name_start = data_start + 5;
            if name_type == 0 && name_start.checked_add(name_len)? <= data_end {
                return String::from_utf8(record[name_start..name_start + name_len].to_vec()).ok();
            }
        }
        pos = data_end;
    }
    None
}

fn should_route_tls_to_private(record: &[u8]) -> bool {
    extract_tls_sni(record)
        .as_deref()
        .is_some_and(is_official_sdk_host)
}

fn connect_without_hook(target: SocketAddrV4) -> std::io::Result<TcpStream> {
    BYPASS_CONNECT_HOOK.set(true);
    let result = TcpStream::connect(target);
    BYPASS_CONNECT_HOOK.set(false);
    result
}

fn read_initial_prefix(stream: &mut TcpStream, prefix: &mut [u8]) -> std::io::Result<usize> {
    let mut read = 0;
    while read < prefix.len() {
        let count = stream.read(&mut prefix[read..])?;
        if count == 0 {
            break;
        }
        read += count;
    }
    Ok(read)
}

fn rewrite_tls_sni(record: &mut Vec<u8>, target_host: &str) -> Result<()> {
    if record.len() < 5 || record[0] != 0x16 {
        return Ok(());
    }
    let handshake_start = 5;
    if record.len() < handshake_start + 4 || record[handshake_start] != 1 {
        return Ok(());
    }
    let handshake_len = u32::from_be_bytes([
        0,
        record[handshake_start + 1],
        record[handshake_start + 2],
        record[handshake_start + 3],
    ]) as usize;
    let body_start = handshake_start + 4;
    let body_end = body_start + handshake_len;
    if body_end > record.len() || handshake_len < 34 {
        return Ok(());
    }

    let mut cursor = body_start + 34;
    if cursor >= body_end {
        return Ok(());
    }
    let session_len = record[cursor] as usize;
    cursor += 1 + session_len;
    if cursor + 2 > body_end {
        return Ok(());
    }
    let cipher_len = u16::from_be_bytes([record[cursor], record[cursor + 1]]) as usize;
    cursor += 2 + cipher_len;
    if cursor >= body_end {
        return Ok(());
    }
    let compression_len = record[cursor] as usize;
    cursor += 1 + compression_len;
    if cursor + 2 > body_end {
        return Ok(());
    }
    let extensions_len = u16::from_be_bytes([record[cursor], record[cursor + 1]]) as usize;
    let extensions_start = cursor + 2;
    let extensions_end = extensions_start + extensions_len;
    if extensions_end > body_end {
        return Ok(());
    }

    let target = target_host.as_bytes();
    if target.len() > u8::MAX as usize {
        return Err(anyhow::anyhow!("TLS SNI host is too long"));
    }
    let mut pos = extensions_start;
    while pos + 4 <= extensions_end {
        let extension_type = u16::from_be_bytes([record[pos], record[pos + 1]]);
        let extension_len = u16::from_be_bytes([record[pos + 2], record[pos + 3]]) as usize;
        let data_start = pos + 4;
        let data_end = data_start + extension_len;
        if data_end > extensions_end {
            break;
        }
        if extension_type == 0 && extension_len >= 5 {
            let list_len =
                u16::from_be_bytes([record[data_start], record[data_start + 1]]) as usize;
            let name_type = record[data_start + 2];
            let name_len_offset = data_start + 3;
            let name_start = data_start + 5;
            if name_type == 0
                && list_len >= 3
                && name_start
                    + u16::from_be_bytes([record[name_len_offset], record[name_len_offset + 1]])
                        as usize
                    <= data_end
            {
                let old_len =
                    u16::from_be_bytes([record[name_len_offset], record[name_len_offset + 1]])
                        as usize;
                let original_host =
                    String::from_utf8_lossy(&record[name_start..name_start + old_len]).into_owned();
                let delta = target.len() as isize - old_len as isize;
                record.splice(name_start..name_start + old_len, target.iter().copied());
                adjust_u16(
                    &mut record[name_len_offset..name_len_offset + 2],
                    target.len(),
                )?;
                adjust_u16(
                    &mut record[data_start..data_start + 2],
                    (list_len as isize + delta) as usize,
                )?;
                adjust_u16(
                    &mut record[pos + 2..pos + 4],
                    (extension_len as isize + delta) as usize,
                )?;
                adjust_u24(
                    &mut record[handshake_start + 1..handshake_start + 4],
                    (handshake_len as isize + delta) as usize,
                )?;
                let record_len = u16::from_be_bytes([record[3], record[4]]) as isize;
                adjust_u16(&mut record[3..5], (record_len + delta) as usize)?;
                crate::diagnostics::event(&format!(
                    "game tls SNI rewrite {} -> {}",
                    original_host, target_host
                ));
                return Ok(());
            }
        }
        pos = data_end;
    }
    crate::diagnostics::event("game tls SNI not present; private TLS endpoint selected");
    Ok(())
}

fn adjust_u16(bytes: &mut [u8], value: usize) -> Result<()> {
    if bytes.len() != 2 || value > u16::MAX as usize {
        return Err(anyhow::anyhow!("TLS length exceeds u16"));
    }
    bytes.copy_from_slice(&(value as u16).to_be_bytes());
    Ok(())
}

fn adjust_u24(bytes: &mut [u8], value: usize) -> Result<()> {
    if bytes.len() != 3 || value > 0x00ff_ffff {
        return Err(anyhow::anyhow!("TLS handshake length exceeds u24"));
    }
    bytes.copy_from_slice(&[(value >> 16) as u8, (value >> 8) as u8, value as u8]);
    Ok(())
}

fn is_tls_client_hello(prefix: &[u8]) -> bool {
    prefix.len() >= 3 && prefix[0] == 0x16 && prefix[1] == 0x03 && prefix[2] <= 0x04
}

fn hex_prefix(prefix: &[u8]) -> String {
    prefix
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

#[cfg(test)]
mod tests {
    use super::{
        extract_tls_sni, ipv4_mapped_bytes, is_configured_proxy_endpoint, is_tls_client_hello,
        mapped_ipv4, parse_connect_host, should_route_tls_to_private,
    };
    use crate::config::ProxyEndpoint;
    use std::net::Ipv4Addr;

    #[test]
    fn detects_tls_client_hello_records() {
        assert!(is_tls_client_hello(&[0x16, 0x03, 0x01, 0x01, 0x00]));
        assert!(is_tls_client_hello(&[0x16, 0x03, 0x03, 0x00, 0xf1]));
    }

    #[test]
    fn keeps_game_protocol_out_of_tls_route() {
        assert!(!is_tls_client_hello(&[0x20, 0x00, 0x00, 0x00, 0x01]));
        assert!(!is_tls_client_hello(&[0x16, 0x04, 0x01, 0x01, 0x00]));
        assert!(!is_tls_client_hello(&[0x16, 0x03]));
    }

    #[test]
    fn routes_sdk_sni_to_private_tls() {
        let hello = tls_client_hello("game-re-en-service.sl916.com");
        assert_eq!(
            extract_tls_sni(&hello).as_deref(),
            Some("game-re-en-service.sl916.com")
        );
        assert!(should_route_tls_to_private(&hello));
    }

    #[test]
    fn leaves_crash_reporting_tls_on_the_official_route() {
        let hello = tls_client_hello("pc.crashsight.wetest.net");
        assert_eq!(
            extract_tls_sni(&hello).as_deref(),
            Some("pc.crashsight.wetest.net")
        );
        assert!(!should_route_tls_to_private(&hello));
    }

    #[test]
    fn recognizes_ipv4_mapped_ipv6_addresses() {
        let ip = Ipv4Addr::new(43, 174, 224, 9);
        assert_eq!(mapped_ipv4(ipv4_mapped_bytes(ip)), Some(ip));
        assert_eq!(mapped_ipv4([0; 16]), None);
    }

    #[test]
    fn parses_only_http_connect_targets() {
        assert_eq!(
            parse_connect_host(
                b"CONNECT game-re-en-service.sl916.com:443 HTTP/1.1\r\nHost: game-re-en-service.sl916.com:443\r\n\r\n"
            )
            .as_deref(),
            Some("game-re-en-service.sl916.com")
        );
        assert_eq!(parse_connect_host(b"GET / HTTP/1.1\r\n\r\n"), None);
    }

    #[test]
    fn intercepts_only_the_configured_loopback_proxy() {
        let proxy = ProxyEndpoint {
            ipv4: Ipv4Addr::LOCALHOST,
            port: 8080,
        };
        assert!(is_configured_proxy_endpoint(
            Some(&proxy),
            Ipv4Addr::LOCALHOST,
            8080
        ));
        assert!(!is_configured_proxy_endpoint(
            Some(&proxy),
            Ipv4Addr::LOCALHOST,
            1250
        ));
        assert!(!is_configured_proxy_endpoint(
            None,
            Ipv4Addr::LOCALHOST,
            8080
        ));
    }

    fn tls_client_hello(host: &str) -> Vec<u8> {
        let host = host.as_bytes();
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0; 32]);
        body.push(0);
        body.extend_from_slice(&[0, 2, 0, 0x2f]);
        body.extend_from_slice(&[1, 0]);

        let name_list_len = 3 + host.len();
        let extension_len = 2 + name_list_len;
        let mut extension = vec![
            0,
            0,
            (extension_len >> 8) as u8,
            extension_len as u8,
            (name_list_len >> 8) as u8,
            name_list_len as u8,
            0,
            (host.len() >> 8) as u8,
            host.len() as u8,
        ];
        extension.extend_from_slice(host);
        body.extend_from_slice(&[(extension.len() >> 8) as u8, extension.len() as u8]);
        body.extend_from_slice(&extension);

        let handshake_len = body.len();
        let mut handshake = vec![
            1,
            (handshake_len >> 16) as u8,
            (handshake_len >> 8) as u8,
            handshake_len as u8,
        ];
        handshake.extend_from_slice(&body);

        let mut record = vec![
            0x16,
            0x03,
            0x01,
            (handshake.len() >> 8) as u8,
            handshake.len() as u8,
        ];
        record.extend_from_slice(&handshake);
        record
    }
}
