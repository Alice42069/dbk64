use std::{
    mem::{size_of, zeroed, MaybeUninit},
    ptr::copy_nonoverlapping,
};

use types::Pointer;
use windows::core::{s, Result};
use windows::Win32::Foundation::{CloseHandle, GENERIC_READ, GENERIC_WRITE};
use windows::Win32::Storage::FileSystem::*;
use windows::Win32::System::IO::DeviceIoControl;

use dataview::{Pod, PodMethods};

use handle::RawHandle;
mod handle;
pub mod types;

// https://github.com/cheat-engine/cheat-engine/blob/master/Cheat%20Engine/dbk32/DBK32functions.pas
const FILE_READ_ACCESS: u32 = 0x0001;
const FILE_WRITE_ACCESS: u32 = 0x0002;
const FILE_RW_ACCESS: u32 = FILE_READ_ACCESS | FILE_WRITE_ACCESS;

const METHOD_BUFFERED: u32 = 0;
const FILE_DEVICE_UNKNOWN: u32 = 0x00000022;
const IOCTL_UNKNOWN_BASE: u32 = FILE_DEVICE_UNKNOWN;

const IOCTL_CE_READMEMORY: u32 =
    (IOCTL_UNKNOWN_BASE << 16) | (0x0800 << 2) | METHOD_BUFFERED | (FILE_RW_ACCESS << 14);

const IOCTL_CE_WRITEMEMORY: u32 =
    (IOCTL_UNKNOWN_BASE << 16) | (0x0801 << 2) | METHOD_BUFFERED | (FILE_RW_ACCESS << 14);

const IOCTL_CE_OPENPROCESS: u32 =
    (IOCTL_UNKNOWN_BASE << 16) | (0x0802 << 2) | METHOD_BUFFERED | (FILE_RW_ACCESS << 14);

const IOCTL_CE_GETPEPROCESS: u32 =
    (IOCTL_UNKNOWN_BASE << 16) | (0x0805 << 2) | METHOD_BUFFERED | (FILE_RW_ACCESS << 14);

const SECTION_BASE_ADDRESS_OFFSETS: [i32; 7] =
    [0x0520, 0x03C8, 0x03C0, 0x03B0, 0x0270, 0x01D0, 0x01F8];

pub struct DBK64 {
    process_id: u64,
    handle: RawHandle,
}

impl DBK64 {
    pub fn open(process_id: u64) -> Result<Self> {
        let handle = unsafe {
            CreateFileA(
                s!("\\\\.\\dbk64"),
                GENERIC_READ.0 | GENERIC_WRITE.0,
                FILE_SHARE_MODE(0),
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )?
        };

        let dbk64 = Self {
            process_id,
            handle: handle.into(),
        };

        let _ = dbk64.openprocess(dbk64.process_id as u32).unwrap();

        Ok(dbk64)
    }

    pub fn get_base_address(&self) -> Option<u64> {
        let e_process = self.getpeprocess(self.process_id as u32)?;

        for i in SECTION_BASE_ADDRESS_OFFSETS {
            let address = self.read::<u64>(e_process + i as u64).ok()?;

            if address > 0 {
                return Some(address);
            }
        }

        return None;
    }

    // most functions below are taken from: https://github.com/memflow/memflow/blob/main/memflow/src/mem/memory_view/mod.rs
    #[allow(clippy::uninit_assumed_init)]
    pub fn read<T: Pod + Sized>(&self, address: u64) -> Result<T> {
        let mut object: T = unsafe { MaybeUninit::uninit().assume_init() };
        self.read_into(address, &mut object)?;
        Ok(object)
    }

    pub fn read_into<T: Pod + ?Sized>(&self, address: u64, out: &mut T) -> Result<()> {
        self.read_raw_into(address, out.as_bytes_mut())
    }

    pub fn read_raw(&self, address: u64, length: usize) -> Result<Vec<u8>> {
        let mut buffer = vec![0u8; length];
        self.read_raw_into(address, &mut buffer)?;
        Ok(buffer)
    }

    pub fn read_raw_into(&self, mut address: u64, buffer: &mut [u8]) -> Result<()> {
        let mut start = 0;

        while start < buffer.len() {
            let chunk_size = (buffer.len() - start).min(u16::MAX as usize);

            let chunk = &mut buffer[start..start + chunk_size];

            self.readmemory(self.process_id, address, chunk)?;

            start += chunk_size;
            address += chunk_size as u64;
        }

        Ok(())
    }

    pub fn read_pointer<T: Pod + Sized>(&self, pointer: Pointer<T>) -> Result<T> {
        Ok(self.read(pointer.inner)?)
    }

    pub fn read_pointer_into<T: Pod + Sized>(
        &self,
        pointer: Pointer<T>,
        out: &mut T,
    ) -> Result<()> {
        self.read_into(pointer.inner, out)
    }

    pub fn read_utf8(&self, address: u64, max_length: usize) -> Result<String> {
        let mut buffer = vec![0; max_length];

        self.read_raw_into(address, &mut buffer).unwrap();

        if let Some((n, _)) = buffer.iter().enumerate().find(|(_, c)| **c == 0_u8) {
            buffer.truncate(n);
        }

        Ok(String::from_utf8(buffer)?)
    }

    pub fn write<T: Pod + ?Sized>(&self, address: u64, data: &T) -> Result<()> {
        self.write_raw(address, data.as_bytes())
    }

    pub fn write_raw(&self, mut address: u64, data: &[u8]) -> Result<()> {
        let mut start = 0;

        while start < data.len() {
            let chunk_size = (data.len() - start).min(256 as usize);

            let chunk = &data[start..start + chunk_size];

            self.writememory(self.process_id, address, chunk)?;

            start += chunk_size;
            address += chunk_size as u64;
        }

        Ok(())
    }

    pub fn write_pointer<T: Pod + ?Sized>(&self, pointer: Pointer<T>, data: &T) -> Result<()> {
        self.write(pointer.inner, data)
    }

    fn openprocess(&self, process_id: u32) -> Option<OpenProcessOutput> {
        if process_id == 0 {
            return None;
        }

        let mut output = OpenProcessOutput {
            processhandle: RawHandle::null(),
            special: 0,
        };

        let mut x = 0_u32;

        unsafe {
            if DeviceIoControl(
                self.handle.handle(),
                IOCTL_CE_OPENPROCESS,
                Some(&process_id as *const _ as *const _),
                4,
                Some(&mut output as *mut _ as *mut _),
                size_of::<OpenProcessOutput>() as _,
                Some(&mut x as *mut _ as *mut _),
                None,
            )
            .is_err()
            {
                return None;
            }
        }

        Some(output)
    }

    fn getpeprocess(&self, processid: u32) -> Option<u64> {
        let mut peprocess = 0_u64;
        let mut bytesreturned = 0_u32;

        unsafe {
            if DeviceIoControl(
                self.handle.handle(),
                IOCTL_CE_GETPEPROCESS,
                Some(&processid as *const _ as *const _),
                size_of::<u32>() as u32,
                Some(&mut peprocess as *mut _ as *mut _),
                size_of::<u64>() as u32,
                Some(&mut bytesreturned),
                None,
            )
            .is_err()
            {
                return None;
            }
        }

        Some(peprocess)
    }

    fn readmemory(&self, processid: u64, startaddress: u64, bytestoread: &mut [u8]) -> Result<()> {
        if bytestoread.len() > u16::MAX as usize {
            panic!("Buffer size exceeds maximum allowable size.");
        }

        let request = ReadMemoryInput {
            processid,
            startaddress,
            bytestoread: bytestoread.len() as u16,
        };

        let mut bytes_read = 0u32;

        unsafe {
            DeviceIoControl(
                self.handle.handle(),
                IOCTL_CE_READMEMORY,
                Some(&request as *const _ as *const _),
                size_of::<ReadMemoryInput>() as u32,
                Some(bytestoread.as_mut_ptr() as *mut _),
                bytestoread.len() as u32,
                Some(&mut bytes_read),
                None,
            )?;
        }

        Ok(())
    }

    fn writememory(&self, processid: u64, startaddress: u64, bytestowrite: &[u8]) -> Result<()> {
        if bytestowrite.len() > u16::MAX as usize {
            panic!("Data size exceeds maximum allowable size.");
        }

        let input = WriteMemoryInput {
            processid,
            startaddress,
            bytestowrite: bytestowrite.len() as u16,
        };

        let input_size = size_of::<WriteMemoryInput>();
        let total_size = input_size + bytestowrite.len();

        if total_size > 512 {
            panic!("Total request size exceeds 512 bytes.");
        }

        let mut ao: [u8; 512] = unsafe { zeroed() };

        unsafe {
            copy_nonoverlapping(&input as *const _ as *const u8, ao.as_mut_ptr(), input_size);

            copy_nonoverlapping(
                bytestowrite.as_ptr(),
                ao.as_mut_ptr().add(input_size),
                bytestowrite.len(),
            );
        }

        let mut bytes_returned = 0_u32;

        unsafe {
            DeviceIoControl(
                self.handle.handle(),
                IOCTL_CE_WRITEMEMORY,
                Some(ao.as_ptr() as *const _),
                total_size as u32,
                None,
                0,
                Some(&mut bytes_returned),
                None,
            )?;
        }

        Ok(())
    }
}

impl Drop for DBK64 {
    fn drop(&mut self) {
        if self.handle.is_valid() {
            unsafe {
                let _ = CloseHandle(self.handle.handle());
            }
        }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct OpenProcessOutput {
    pub processhandle: RawHandle,
    pub special: u8,
}

#[repr(C, packed)]
struct WriteMemoryInput {
    processid: u64,
    startaddress: u64,
    bytestowrite: u16,
}

#[repr(C)]
struct ReadMemoryInput {
    processid: u64,
    startaddress: u64,
    // size
    bytestoread: u16,
}
