use std::net::Ipv4Addr;

use anyhow::Result;
use ilhook::x64::Registers;
use windows::Win32::Networking::WinSock::{AF_INET, SOCKADDR_IN};

use super::{MhyContext, MhyModule, ModuleType};

pub struct Socket;

impl MhyModule for MhyContext<Socket> {
    unsafe fn init(&mut self) -> Result<()> {
        crate::config::get().map_err(anyhow::Error::msg)?;
        let addr = self.get_export("Ws2_32.dll", "connect")?;
        self.interceptor.attach(addr, on_connect)?;
        crate::diagnostics::event("socket hook attached");
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

    let Ok(config) = crate::config::get() else {
        return;
    };

    if port == 443 && config.tls.ipv4 == Some(ip) {
        crate::diagnostics::event(&format!(
            "sdk tls redirect source={key} target={ip}:{}",
            config.tls.port
        ));
        sockaddr.sin_port = config.tls.port.to_be();
        return;
    }

    //(43, 175, 234, 39) //port == 12004
    if ip == Ipv4Addr::new(43, 163, 62, 120) && port == 443 {
        let Some(redir_ip) = config.game.ipv4 else {
            println!("No game.ipv4 configured; leaving {key} unchanged");
            return;
        };
        println!("Redirecting {key} -> {redir_ip}:{}", config.game.port);
        crate::diagnostics::event(&format!(
            "game redirect source={key} target={redir_ip}:{}",
            config.game.port
        ));
        sockaddr.sin_addr.S_un.S_addr = u32::from(redir_ip).to_be();
        sockaddr.sin_port = config.game.port.to_be();
    }
}
