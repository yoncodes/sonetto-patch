use std::{ffi::c_void, sync::LazyLock};

use windows::{
    core::s,
    Win32::System::{
        LibraryLoader::{GetModuleHandleA, GetProcAddress},
        Memory,
    },
};

pub static GAME_ASSEMBLY_BASE: LazyLock<usize> =
    LazyLock::new(|| unsafe { GetModuleHandleA(s!("GameAssembly.dll")).unwrap().0 as usize });

pub unsafe fn il2cpp_string_new(cstr: *const u8) -> usize {
    type Function = unsafe extern "system" fn(*const u8) -> usize;

    static FUNCTION: LazyLock<Option<Function>> = LazyLock::new(|| {
        let module = unsafe { GetModuleHandleA(s!("GameAssembly.dll")) }.ok()?;
        let function = unsafe { GetProcAddress(module, s!("il2cpp_string_new")) }?;
        Some(unsafe {
            std::mem::transmute::<unsafe extern "system" fn() -> isize, Function>(function)
        })
    });

    FUNCTION.map_or(0, |function| function(cstr))
}

#[inline]
pub unsafe fn read_csharp_string(s: usize) -> String {
    let str_length = *(s.wrapping_add(16) as *const u32);
    let str_ptr = s.wrapping_add(20) as *const u8;

    String::from_utf16le_lossy(std::slice::from_raw_parts(
        str_ptr,
        (str_length * 2) as usize,
    ))
}

pub unsafe fn disable_memory_protection() {
    let ntdll = GetModuleHandleA(s!("ntdll.dll")).unwrap();
    let proc_addr = GetProcAddress(ntdll, s!("NtProtectVirtualMemory")).unwrap();

    let nt_func = if GetProcAddress(ntdll, s!("wine_get_version")).is_some() {
        GetProcAddress(ntdll, s!("NtPulseEvent")).unwrap()
    } else {
        GetProcAddress(ntdll, s!("NtQuerySection")).unwrap()
    };

    let mut prot = Memory::PAGE_EXECUTE_READWRITE;
    Memory::VirtualProtect(proc_addr as *const usize as *mut c_void, 1, prot, &mut prot).unwrap();

    let routine = nt_func as *mut u32;
    let routine_val = *(routine as *const usize);

    let lower_bits_mask = !(0xFFu64 << 32);
    let lower_bits = routine_val & lower_bits_mask as usize;

    let offset_val = *((routine as usize + 4) as *const u32);
    let upper_bits = ((offset_val as usize).wrapping_sub(1) as usize) << 32;

    let result = lower_bits | upper_bits;

    *(proc_addr as *mut usize) = result;
    Memory::VirtualProtect(proc_addr as *const usize as *mut c_void, 1, prot, &mut prot).unwrap();
}
