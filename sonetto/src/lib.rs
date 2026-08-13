use std::{sync::RwLock, time::Duration};

use lazy_static::lazy_static;
use windows::core::PCSTR;
//use windows::Win32::System::Console;
use windows::Win32::System::SystemServices::DLL_PROCESS_ATTACH;
use windows::Win32::{Foundation::HINSTANCE, System::LibraryLoader::GetModuleHandleA};

mod config;
mod diagnostics;
mod interceptor;
mod modules;
mod util;

use crate::modules::{MhyContext, ModuleManager, Network, Socket};

#[allow(clippy::manual_c_str_literals)]
unsafe fn thread_func() {
    diagnostics::event("dll attached; waiting for GameAssembly.dll");
    while GetModuleHandleA(PCSTR(b"GameAssembly.dll\0".as_ptr())).is_err() {
        std::thread::sleep(Duration::from_millis(200));
    }

    diagnostics::event("GameAssembly.dll ready");

    //std::thread::sleep(Duration::from_secs(1));

    util::disable_memory_protection();
    //let _ = Console::AllocConsole();

    println!("Reverse 1999 patch\nMade by yoncodes\nTo work with enigma:");
    println!("Base: {:X}", *util::GAME_ASSEMBLY_BASE);

    let mut module_manager = MODULE_MANAGER.write().unwrap();

    if let Err(error) = module_manager.enable(MhyContext::<Network>::new()) {
        diagnostics::event(&format!("network initialization failed: {error:#}"));
        println!("[ERROR] Network initialization failed: {error:#}");
    }
    if let Err(error) = module_manager.enable(MhyContext::<Socket>::new()) {
        diagnostics::event(&format!("socket initialization failed: {error:#}"));
        println!("[ERROR] Socket initialization failed: {error:#}");
        return;
    }
    diagnostics::event("all hooks initialized without IL2CPP exports");
    println!("Successfully initialized network hooks without IL2CPP exports!");
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
