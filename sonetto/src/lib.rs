use std::{ffi::CString, sync::RwLock};

use lazy_static::lazy_static;
use windows::core::PCSTR;
//use windows::Win32::System::Console;
use windows::Win32::System::SystemServices::DLL_PROCESS_ATTACH;
use windows::Win32::{
    Foundation::{CloseHandle, HINSTANCE},
    System::{
        LibraryLoader::LoadLibraryA,
        Threading::{CreateEventA, GetCurrentProcessId, SetEvent},
    },
};

mod config;
mod diagnostics;
mod interceptor;
mod modules;
use crate::modules::{MhyContext, ModuleManager, Network, Socket};

#[allow(clippy::manual_c_str_literals)]
unsafe fn thread_func() {
    diagnostics::event("dll attached; loading network hook dependencies");
    for (name, bytes) in [
        ("Ws2_32.dll", b"Ws2_32.dll\0".as_slice()),
        ("WinHttp.dll", b"WinHttp.dll\0".as_slice()),
        ("Crypt32.dll", b"Crypt32.dll\0".as_slice()),
    ] {
        if let Err(error) = LoadLibraryA(PCSTR(bytes.as_ptr())) {
            diagnostics::event(&format!("network dependency load failed: {name}: {error}"));
            return;
        }
    }
    diagnostics::event("network hook dependencies loaded before GameAssembly.dll");

    let mut module_manager = MODULE_MANAGER.write().unwrap();

    if let Err(error) = module_manager.enable(MhyContext::<Socket>::new()) {
        diagnostics::event(&format!("socket initialization failed: {error:#}"));
        return;
    }
    if let Err(error) = module_manager.enable(MhyContext::<Network>::new()) {
        diagnostics::event(&format!("network initialization failed: {error:#}"));
        return;
    }
    diagnostics::event("all network hooks initialized before GameAssembly.dll");
    signal_launcher_ready();
}

unsafe fn signal_launcher_ready() {
    let event_name = CString::new(format!(
        "Local\\SonettoNetworkReady-{}",
        GetCurrentProcessId()
    ))
    .expect("readiness event name cannot contain NUL");
    match CreateEventA(None, true, false, PCSTR(event_name.as_ptr() as *const u8)) {
        Ok(event) => {
            if let Err(error) = SetEvent(event) {
                diagnostics::event(&format!("launcher readiness signal failed: {error}"));
            } else {
                diagnostics::event("launcher readiness signaled");
            }
            let _ = CloseHandle(event);
        }
        Err(error) => diagnostics::event(&format!(
            "launcher readiness event creation failed: {error}"
        )),
    }
}

lazy_static! {
    static ref MODULE_MANAGER: RwLock<ModuleManager> = RwLock::new(ModuleManager::default());
}

#[no_mangle]
#[allow(non_snake_case)]
unsafe extern "system" fn DllMain(_: HINSTANCE, call_reason: u32, _: *mut ()) -> bool {
    if call_reason == DLL_PROCESS_ATTACH {
        std::thread::spawn(|| thread_func());
    }

    true
}
