use std::ffi::CString;
use std::sync::LazyLock;

use super::{MhyContext, MhyModule, ModuleType};
use crate::util::{import, read_csharp_string};
use anyhow::Result;
use ilhook::x64::Registers;

const WEB_REQUEST_UTILS_MAKE_INITIAL_URL: usize = 0x3e4d8a0;
const BROWSER_LOAD_URL: usize = 0x3e79830;
const SET_REQUEST_HEADER: usize = 0x3e48860;

static HOST_CSTRING: LazyLock<CString> = LazyLock::new(|| CString::new("127.0.0.1").unwrap());

pub struct Network;

impl MhyModule for MhyContext<Network> {
    unsafe fn init(&mut self) -> Result<()> {
        self.interceptor.attach(
            self.assembly_base + WEB_REQUEST_UTILS_MAKE_INITIAL_URL,
            on_make_initial_url,
        )?;

        self.interceptor
            .attach(self.assembly_base + BROWSER_LOAD_URL, on_browser_load_url)?;

        self.interceptor.attach(
            self.assembly_base + SET_REQUEST_HEADER,
            on_set_request_header,
        )?;

        Ok(())
    }

    unsafe fn de_init(&mut self) -> Result<()> {
        Ok(())
    }

    fn get_module_type(&self) -> super::ModuleType {
        ModuleType::Network
    }
}

import!(il2cpp_string_new(cstr: *const u8) -> usize = 0x5277B0);

unsafe extern "win64" fn on_make_initial_url(reg: *mut Registers, _: usize) {
    let url = read_csharp_string((*reg).rcx as usize);

    if !url.contains("sl916.com") {
        println!("Leaving {url} as is!");
        return;
    }

    let mut new_url = String::from("http://127.0.0.1:21000");
    url.split('/').skip(3).for_each(|s| {
        new_url.push('/');
        new_url.push_str(s);
    });

    if !url.contains("C:/") {
        println!("Redirect: {url} -> {new_url}");

        let cstr = CString::new(new_url.as_str()).unwrap();
        let new_ptr = il2cpp_string_new(cstr.as_ptr() as *const u8);
        if new_ptr == 0 {
            println!("[ERROR] il2cpp_string_new returned null — RVA 0x2EAD30 may be stale");
            return;
        }
        (*reg).rcx = new_ptr as u64;
    }
}

unsafe extern "win64" fn on_browser_load_url(reg: *mut Registers, _: usize) {
    let url_ptr = (*reg).rdx as usize;
    if url_ptr == 0 {
        return;
    }

    let url = read_csharp_string(url_ptr);

    // Skip about:blank or anything you want to exclude
    if url == "about:blank" {
        return;
    }

    if url.contains("game.local") {
        return;
    }

    // Rewrite to local server
    let mut new_url = String::from("https://127.0.0.1:21000");
    url.split('/').skip(3).for_each(|s| {
        new_url.push('/');
        new_url.push_str(s);
    });

    println!("Browser::LoadURL: {url} → {new_url}");

    // Actually patch the pointer passed into the method
    /*  let cstr = CString::new(new_url).unwrap();
    let new_ptr = il2cpp_string_new(cstr.as_ptr() as *const u8);
    (*reg).rdx = new_ptr as u64;*/
}

unsafe extern "win64" fn on_set_request_header(reg: *mut Registers, _: usize) {
    if (*reg).rdx == 0 || (*reg).r8 == 0 {
        return;
    }
    let key = read_csharp_string((*reg).rdx as usize);
    let value = read_csharp_string((*reg).r8 as usize);

    if key.is_empty() || value.is_empty() {
        return;
    }

    if key.eq_ignore_ascii_case("host") {
        println!("[SetRequestHeader] Rewriting Host: {value} → 127.0.0.1");

        let new_ptr = il2cpp_string_new(HOST_CSTRING.as_ptr() as *const u8);
        (*reg).r8 = new_ptr as u64;
    } else {
        println!("[SetRequestHeader] {key}: {value}");
    }
}
