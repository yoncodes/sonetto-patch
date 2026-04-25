use std::{collections::HashMap, net::Ipv4Addr};

use anyhow::Result;
use ilhook::x64::Registers;
use std::sync::LazyLock;
use windows::Win32::Networking::WinSock::{AF_INET, SOCKADDR_IN};

use super::{MhyContext, MhyModule, ModuleType};

pub struct Socket;

impl MhyModule for MhyContext<Socket> {
    unsafe fn init(&mut self) -> Result<()> {
        let addr = self.get_export("Ws2_32.dll", "connect")?;
        self.interceptor.attach(addr, on_connect)?;
        println!("[*] Socket hook attached to connect()");
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
    let sockaddr_ptr = (*reg).rdx as *mut SOCKADDR_IN;

    if sockaddr_ptr.is_null() {
        return;
    }

    let sockaddr = &mut *sockaddr_ptr;

    if sockaddr.sin_family.0 != AF_INET.0 {
        return;
    }

    let ip = Ipv4Addr::from(u32::from_be(sockaddr.sin_addr.S_un.S_addr));
    let port = u16::from_be(sockaddr.sin_port);

    let key = format!("{ip}:{port}");
    println!("[connect] IP: {ip}, Port: {port}");

    //(43, 175, 234, 39) //port == 12004
    if ip == Ipv4Addr::new(43, 163, 62, 120) && port == 443 {
        println!("Overriding {ip}:{port} → 127.0.0.1:12004");
        sockaddr.sin_addr.S_un.S_addr = u32::from(Ipv4Addr::LOCALHOST).to_be();
        sockaddr.sin_port = 12004u16.to_be();
        return;
    }

    if let Some((redir_ip, redir_port)) = get_target_map().get(&key) {
        println!("Redirecting {key} → {redir_ip}:{redir_port}");

        sockaddr.sin_addr.S_un.S_addr = u32::from(*redir_ip).to_be();
        sockaddr.sin_port = redir_port.to_be();
    }
}

fn get_target_map() -> &'static HashMap<String, (Ipv4Addr, u16)> {
    static TARGET_MAP: LazyLock<HashMap<String, (Ipv4Addr, u16)>> = LazyLock::new(|| {
        HashMap::from([("43.175.234.39:12004".into(), (Ipv4Addr::LOCALHOST, 12004))])
    });
    &TARGET_MAP
}
