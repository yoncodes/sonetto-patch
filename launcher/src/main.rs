use std::ffi::CString;

use std::ptr::null_mut;
use windows::core::{s, PCSTR, PSTR};
use windows::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, WAIT_OBJECT_0};
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows::Win32::System::Memory::{
    VirtualAllocEx, VirtualFreeEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE,
};
use windows::Win32::System::Threading::{
    CreateEventA, CreateProcessA, CreateRemoteThread, ResumeThread, TerminateProcess,
    WaitForSingleObject, CREATE_SUSPENDED, PROCESS_INFORMATION, STARTUPINFOA,
};

const GAME_EXECUTABLE: PCSTR = s!("reverse1999.exe");
const INJECT_DLL: &str = "sonetto.dll";
const HOOK_READY_TIMEOUT_MS: u32 = 15_000;

fn ready_event_name(process_id: u32) -> CString {
    CString::new(format!("Local\\SonettoNetworkReady-{process_id}"))
        .expect("readiness event name cannot contain NUL")
}

#[allow(clippy::missing_transmute_annotations)]
fn inject_standard(h_target: HANDLE, dll_path: &str) -> bool {
    unsafe {
        let loadlib = GetProcAddress(
            GetModuleHandleA(s!("kernel32.dll")).unwrap(),
            s!("LoadLibraryA"),
        )
        .unwrap();

        let dll_path_cstr = CString::new(dll_path).unwrap();
        let dll_path_addr = VirtualAllocEx(
            h_target,
            None,
            dll_path_cstr.to_bytes_with_nul().len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if dll_path_addr.is_null() {
            println!("VirtualAllocEx failed. Last error: {:?}", GetLastError());
            return false;
        }

        WriteProcessMemory(
            h_target,
            dll_path_addr,
            dll_path_cstr.as_ptr() as _,
            dll_path_cstr.to_bytes_with_nul().len(),
            None,
        )
        .unwrap();

        let h_thread = CreateRemoteThread(
            h_target,
            None,
            0,
            Some(std::mem::transmute(loadlib)),
            Some(dll_path_addr),
            0,
            None,
        )
        .unwrap();

        WaitForSingleObject(h_thread, 0xFFFFFFFF);

        VirtualFreeEx(h_target, dll_path_addr, 0, MEM_RELEASE).unwrap();
        CloseHandle(h_thread).unwrap();
        true
    }
}

#[allow(clippy::unnecessary_mut_passed)]
fn main() {
    let current_dir = std::env::current_dir().unwrap();
    let dll_path = current_dir.join(INJECT_DLL);
    if !dll_path.is_file() {
        println!("{INJECT_DLL} not found");
        return;
    }

    let mut proc_info = PROCESS_INFORMATION::default();
    let mut startup_info = STARTUPINFOA::default();

    unsafe {
        CreateProcessA(
            GAME_EXECUTABLE,
            PSTR(null_mut()),
            None,
            None,
            false,
            CREATE_SUSPENDED,
            None,
            None,
            &mut startup_info,
            &mut proc_info,
        )
        .unwrap();

        let event_name = ready_event_name(proc_info.dwProcessId);
        let ready_event =
            CreateEventA(None, true, false, PCSTR(event_name.as_ptr() as *const u8)).unwrap();

        if inject_standard(proc_info.hProcess, dll_path.to_str().unwrap()) {
            let wait_result = WaitForSingleObject(ready_event, HOOK_READY_TIMEOUT_MS);
            if wait_result == WAIT_OBJECT_0 {
                ResumeThread(proc_info.hThread);
            } else {
                println!(
                    "Network hooks did not become ready within {} seconds; game launch aborted.",
                    HOOK_READY_TIMEOUT_MS / 1000
                );
                let _ = TerminateProcess(proc_info.hProcess, 1);
            }
        } else {
            let _ = TerminateProcess(proc_info.hProcess, 1);
        }

        CloseHandle(ready_event).unwrap();
        CloseHandle(proc_info.hThread).unwrap();
        CloseHandle(proc_info.hProcess).unwrap();
    }
}
