use std::{
    ffi::{c_void, CStr, CString},
    sync::OnceLock,
};

use anyhow::{anyhow, Result};
use ilhook::x64::{Registers, RetnRoutine};

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

#[repr(C)]
struct CertChainPolicyStatus {
    cb_size: u32,
    error: u32,
    chain_index: i32,
    element_index: i32,
    extra_policy_status: *mut c_void,
}

#[repr(C)]
struct CurrentUserIeProxyConfig {
    auto_detect: i32,
    auto_config_url: *mut u16,
    proxy: *mut u16,
    proxy_bypass: *mut u16,
}

#[repr(C)]
struct WinHttpProxyInfo {
    access_type: u32,
    proxy: *mut u16,
    proxy_bypass: *mut u16,
}

const CERT_E_CN_NO_MATCH: u32 = 0x800B_010F;
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

        attach_optional_replace(
            self,
            "WinHttp.dll",
            "WinHttpGetIEProxyConfigForCurrentUser",
            on_get_ie_proxy_config,
        );
        attach_optional_replace(
            self,
            "WinHttp.dll",
            "WinHttpGetProxyForUrl",
            on_get_proxy_for_url,
        );

        attach_optional(self, "Ws2_32.dll", "getaddrinfo", on_getaddrinfo);
        attach_optional(self, "Ws2_32.dll", "gethostbyname", on_getaddrinfo);
        attach_optional_replace(
            self,
            "Crypt32.dll",
            "CertVerifyCertificateChainPolicy",
            on_verify_certificate_chain_policy,
        );

        crate::diagnostics::event(
            "network hooks attached with process-local SDK proxy bypass, DNS and certificate compatibility fallbacks",
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

unsafe extern "win64" fn on_get_ie_proxy_config(reg: *mut Registers, _: usize, _: usize) -> usize {
    let config = (*reg).rcx as *mut CurrentUserIeProxyConfig;
    if config.is_null() {
        return 0;
    }
    (*config).auto_detect = 0;
    (*config).auto_config_url = std::ptr::null_mut();
    (*config).proxy = std::ptr::null_mut();
    (*config).proxy_bypass = std::ptr::null_mut();
    crate::diagnostics::event(
        "process-local IE proxy bypass returned to game; system proxy unchanged",
    );
    1
}

unsafe extern "win64" fn on_get_proxy_for_url(
    reg: *mut Registers,
    original: usize,
    _: usize,
) -> usize {
    type Original =
        unsafe extern "system" fn(usize, *const u16, usize, *mut WinHttpProxyInfo) -> i32;
    let original: Original = std::mem::transmute(original);
    let url_ptr = (*reg).rdx as *const u16;
    let proxy_info = (*reg).r9 as *mut WinHttpProxyInfo;

    if !url_ptr.is_null() && !proxy_info.is_null() {
        if let Some(url) = read_wide_string(url_ptr, 2048) {
            if is_official_sdk_url(&url) {
                (*proxy_info).access_type = 1;
                (*proxy_info).proxy = std::ptr::null_mut();
                (*proxy_info).proxy_bypass = std::ptr::null_mut();
                crate::diagnostics::event(&format!(
                    "process-local direct route selected for SDK URL {url}"
                ));
                return 1;
            }
        }
    }

    original((*reg).rcx as usize, url_ptr, (*reg).r8 as usize, proxy_info) as usize
}

unsafe fn attach_optional_replace(
    context: &mut MhyContext<Network>,
    module: &str,
    symbol: &str,
    callback: RetnRoutine,
) {
    let result = context
        .get_export(module, symbol)
        .and_then(|address| context.interceptor.replace(address, callback));
    if let Err(error) = result {
        crate::diagnostics::event(&format!(
            "optional network replacement unavailable: {module}!{symbol}: {error:#}"
        ));
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

unsafe extern "win64" fn on_verify_certificate_chain_policy(
    reg: *mut Registers,
    original: usize,
    _: usize,
) -> usize {
    const CERT_CHAIN_POLICY_SSL: usize = 4;
    const AUTHTYPE_SERVER: u32 = 2;

    type Original = unsafe extern "system" fn(
        usize,
        usize,
        *mut CertChainPolicyPara,
        *mut CertChainPolicyStatus,
    ) -> i32;

    let original: Original = std::mem::transmute(original);
    let policy = (*reg).r8 as *mut CertChainPolicyPara;
    let status = (*reg).r9 as *mut CertChainPolicyStatus;

    let mut rewritten = None;
    if (*reg).rcx as usize == CERT_CHAIN_POLICY_SSL
        && !policy.is_null()
        && !(*policy).extra_policy_para.is_null()
    {
        let https = (*policy).extra_policy_para as *mut HttpsPolicyCallbackData;
        if !https.is_null()
            && (*https).auth_type == AUTHTYPE_SERVER
            && !(*https).server_name.is_null()
        {
            if let Some(host) = read_wide_string((*https).server_name, 512) {
                if is_official_sdk_host(&host) {
                    if let Some(target) = TLS_HOST_WIDE.get() {
                        let original_name = (*https).server_name;
                        (*https).server_name = target.as_ptr() as *mut u16;
                        rewritten = Some((https, original_name, host));
                    }
                }
            }
        }
    }

    let result = original((*reg).rcx as usize, (*reg).rdx as usize, policy, status);

    if let Some((https, original_name, host)) = rewritten {
        (*https).server_name = original_name;
        let target = TLS_HOST_WIDE.get().expect("TLS host initialized");
        crate::diagnostics::event(&format!(
            "sdk certificate host rewrite {host} -> {}",
            String::from_utf16_lossy(&target[..target.len().saturating_sub(1)])
        ));

        if !status.is_null() && should_accept_private_cn_mismatch(&host, (*status).error) {
            (*status).error = 0;
            (*status).chain_index = -1;
            (*status).element_index = -1;
            crate::diagnostics::event(&format!(
                "sdk certificate CN mismatch accepted for redirected host {host}"
            ));
            return 1;
        }
    }

    result as usize
}

fn should_accept_private_cn_mismatch(host: &str, error: u32) -> bool {
    error == CERT_E_CN_NO_MATCH && is_official_sdk_host(host)
}

pub(super) fn is_official_sdk_host(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    host == "sl916.com" || host.ends_with(".sl916.com") || host == "game.local"
}

fn is_official_sdk_url(url: &str) -> bool {
    let authority = url
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(url)
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .rsplit('@')
        .next()
        .unwrap_or_default();
    let host = authority
        .strip_prefix('[')
        .and_then(|value| value.split_once(']').map(|(host, _)| host))
        .or_else(|| authority.split_once(':').map(|(host, _)| host))
        .unwrap_or(authority);
    is_official_sdk_host(host)
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
    use super::{
        is_official_sdk_host, is_official_sdk_url, should_accept_private_cn_mismatch,
        CERT_E_CN_NO_MATCH,
    };

    #[test]
    fn official_sdk_hosts_are_matched_by_exact_suffix() {
        assert!(is_official_sdk_host("gamesdk-en.sl916.com"));
        assert!(is_official_sdk_host("SL916.COM."));
        assert!(is_official_sdk_host("game.local"));
        assert!(!is_official_sdk_host("evilsl916.com"));
        assert!(!is_official_sdk_host("sl916.com.example.org"));
    }

    #[test]
    fn only_cn_mismatch_for_redirected_sdk_hosts_is_accepted() {
        assert!(should_accept_private_cn_mismatch(
            "hotupdate-hw.sl916.com",
            CERT_E_CN_NO_MATCH
        ));
        assert!(!should_accept_private_cn_mismatch(
            "hotupdate-hw.sl916.com",
            0x800B_0109
        ));
        assert!(!should_accept_private_cn_mismatch(
            "example.org",
            CERT_E_CN_NO_MATCH
        ));
    }

    #[test]
    fn official_sdk_urls_bypass_only_the_process_proxy() {
        assert!(is_official_sdk_url(
            "https://game-re-en-service.sl916.com/login"
        ));
        assert!(is_official_sdk_url("hotupdate-hw.sl916.com:443/path"));
        assert!(!is_official_sdk_url(
            "https://pc.crashsight.wetest.net/report"
        ));
    }
}
