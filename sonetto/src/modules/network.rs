use std::{
    ffi::{c_void, CStr, CString},
    sync::OnceLock,
};

use anyhow::{anyhow, Result};
use ilhook::x64::Registers;

use super::{MhyContext, MhyModule, ModuleType};

static TLS_HOST_ANSI: OnceLock<CString> = OnceLock::new();
static TLS_HOST_WIDE: OnceLock<Vec<u16>> = OnceLock::new();

#[repr(C)]
struct CertChainPolicyPara {
    cb_size: u32,
    flags: u32,
    extra_policy_para: *mut c_void,
}

#[repr(C)]
struct HttpsPolicyCallbackData {
    cb_size: u32,
    auth_type: u32,
    checks: u32,
    server_name: *mut u16,
}
pub struct Network;

impl MhyModule for MhyContext<Network> {
    unsafe fn init(&mut self) -> Result<()> {
        let config = crate::config::get().map_err(anyhow::Error::msg)?;
        TLS_HOST_ANSI
            .set(CString::new(config.tls.host.as_str())?)
            .map_err(|_| anyhow!("TLS host was already initialized"))?;
        TLS_HOST_WIDE
            .set(
                config
                    .tls
                    .host
                    .encode_utf16()
                    .chain(std::iter::once(0))
                    .collect(),
            )
            .map_err(|_| anyhow!("TLS host was already initialized"))?;

        let winhttp_connect = self.get_export("winhttp.dll", "WinHttpConnect")?;
        self.interceptor
            .attach(winhttp_connect, on_winhttp_connect)?;

        attach_optional(self, "Ws2_32.dll", "getaddrinfo", on_getaddrinfo);
        attach_optional(self, "Ws2_32.dll", "gethostbyname", on_getaddrinfo);
        attach_optional(
            self,
            "Crypt32.dll",
            "CertVerifyCertificateChainPolicy",
            on_verify_certificate_chain_policy,
        );

        crate::diagnostics::event(
            "network hooks attached at WinHTTP with DNS and certificate compatibility fallbacks",
        );
        Ok(())
    }

    unsafe fn de_init(&mut self) -> Result<()> {
        Ok(())
    }

    fn get_module_type(&self) -> super::ModuleType {
        ModuleType::Network
    }
}

unsafe fn attach_optional(
    context: &mut MhyContext<Network>,
    module: &str,
    symbol: &str,
    callback: ilhook::x64::JmpBackRoutine,
) {
    let result = context
        .get_export(module, symbol)
        .and_then(|address| context.interceptor.attach(address, callback));
    if let Err(error) = result {
        crate::diagnostics::event(&format!(
            "optional network hook unavailable: {module}!{symbol}: {error:#}"
        ));
    }
}

unsafe extern "win64" fn on_winhttp_connect(reg: *mut Registers, _: usize) {
    let host_ptr = (*reg).rdx as *const u16;
    if host_ptr.is_null() {
        return;
    }

    let Some(host) = read_wide_string(host_ptr, 512) else {
        return;
    };
    if !is_official_sdk_host(&host) {
        return;
    }

    let Ok(config) = crate::config::get() else {
        return;
    };
    let Some(target) = TLS_HOST_WIDE.get() else {
        return;
    };

    let original_port = (*reg).r8 as u16;
    (*reg).rdx = target.as_ptr() as u64;
    (*reg).r8 = u64::from(config.tls.port);
    crate::diagnostics::event(&format!(
        "sdk WinHTTP redirect {host}:{} -> {}:{}",
        original_port, config.tls.host, config.tls.port
    ));
}

unsafe extern "win64" fn on_getaddrinfo(reg: *mut Registers, _: usize) {
    let node_ptr = (*reg).rcx as *const i8;
    if node_ptr.is_null() {
        return;
    }

    let Ok(host) = CStr::from_ptr(node_ptr).to_str() else {
        return;
    };
    if !is_official_sdk_host(host) {
        return;
    }

    let Some(target) = TLS_HOST_ANSI.get() else {
        return;
    };
    crate::diagnostics::event(&format!(
        "sdk dns rewrite {host} -> {}",
        target.to_string_lossy()
    ));
    (*reg).rcx = target.as_ptr() as u64;
}

unsafe extern "win64" fn on_verify_certificate_chain_policy(reg: *mut Registers, _: usize) {
    const CERT_CHAIN_POLICY_SSL: usize = 4;
    const AUTHTYPE_SERVER: u32 = 2;

    if (*reg).rcx as usize != CERT_CHAIN_POLICY_SSL {
        return;
    }

    let policy = (*reg).r8 as *mut CertChainPolicyPara;
    if policy.is_null() || (*policy).extra_policy_para.is_null() {
        return;
    }

    let https = (*policy).extra_policy_para as *mut HttpsPolicyCallbackData;
    if https.is_null() || (*https).auth_type != AUTHTYPE_SERVER || (*https).server_name.is_null() {
        return;
    }

    let Some(original) = read_wide_string((*https).server_name, 512) else {
        return;
    };
    if !is_official_sdk_host(&original) {
        return;
    }

    let Some(target) = TLS_HOST_WIDE.get() else {
        return;
    };
    (*https).server_name = target.as_ptr() as *mut u16;
    crate::diagnostics::event(&format!(
        "sdk certificate host rewrite {original} -> {}",
        String::from_utf16_lossy(&target[..target.len().saturating_sub(1)])
    ));
}

fn is_official_sdk_host(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    host == "sl916.com" || host.ends_with(".sl916.com") || host == "game.local"
}

unsafe fn read_wide_string(ptr: *const u16, max_units: usize) -> Option<String> {
    let mut length = 0;
    while length < max_units && *ptr.add(length) != 0 {
        length += 1;
    }
    (length < max_units).then(|| String::from_utf16_lossy(std::slice::from_raw_parts(ptr, length)))
}

#[cfg(test)]
mod tests {
    use super::is_official_sdk_host;

    #[test]
    fn official_sdk_hosts_are_matched_by_exact_suffix() {
        assert!(is_official_sdk_host("gamesdk-en.sl916.com"));
        assert!(is_official_sdk_host("SL916.COM."));
        assert!(is_official_sdk_host("game.local"));
        assert!(!is_official_sdk_host("evilsl916.com"));
        assert!(!is_official_sdk_host("sl916.com.example.org"));
    }
}
