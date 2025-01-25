use std::{
    ffi::CString,
    mem::{size_of, zeroed, MaybeUninit},
    ptr::copy_nonoverlapping,
};

use windows::core::{Result, PCSTR};
use windows::Win32::Foundation::{CloseHandle, GENERIC_READ, GENERIC_WRITE};
use windows::Win32::Storage::FileSystem::*;
use windows::Win32::System::IO::DeviceIoControl;

use dataview::{Pod, PodMethods};

use handle::RawHandle;
mod handle;

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

pub struct DBK64 {
    handle: RawHandle,
}

impl DBK64 {
    pub fn open(name: Option<&'static str>) -> Result<Self> {
        let file_name = CString::new(format!(r"\\.\{}", name.unwrap_or("dbk64"))).unwrap();

        let handle = unsafe {
            CreateFileA(
                PCSTR::from_raw(file_name.as_ptr() as _),
                GENERIC_READ.0 | GENERIC_WRITE.0,
                FILE_SHARE_MODE(0),
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )?
        };

        Ok(Self {
            handle: handle.into(),
        })
    }

    pub fn open_process(&self, process_id: u32) -> Option<OpenProcessOutput> {
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

    #[allow(clippy::uninit_assumed_init)]
    pub fn read<T: Pod + Sized>(&self, process_id: u64, address: u64) -> Result<T> {
        let mut object: T = unsafe { MaybeUninit::uninit().assume_init() };
        self.read_into(process_id, address, &mut object)?;
        Ok(object)
    }

    pub fn read_into<T: Pod + ?Sized>(
        &self,
        process_id: u64,
        address: u64,
        out: &mut T,
    ) -> Result<()> {
        self.read_raw_into(process_id, address, out.as_bytes_mut())
    }

    pub fn read_raw(&self, process_id: u64, address: u64, length: usize) -> Result<Vec<u8>> {
        let mut buffer = vec![0u8; length];
        self.read_raw_into(process_id, address, &mut buffer)?;
        Ok(buffer)
    }

    pub fn read_raw_into(
        &self,
        process_id: u64,
        mut address: u64,
        buffer: &mut [u8],
    ) -> Result<()> {
        let mut start = 0;

        while start < buffer.len() {
            let chunk_size = (buffer.len() - start).min(u16::MAX as usize);

            let chunk = &mut buffer[start..start + chunk_size];

            self.read_memory(process_id, address, chunk)?;

            start += chunk_size;
            address += chunk_size as u64;
        }

        Ok(())
    }

    pub fn write<T: Pod + ?Sized>(&self, process_id: u64, address: u64, data: &T) -> Result<()> {
        self.write_raw(process_id, address, data.as_bytes())
    }

    pub fn write_raw(&self, process_id: u64, mut address: u64, data: &[u8]) -> Result<()> {
        let mut start = 0;

        while start < data.len() {
            let chunk_size = (data.len() - start).min(u16::MAX as usize);

            let chunk = &data[start..start + chunk_size];

            self.write_memory(process_id, address, chunk)?;

            start += chunk_size;
            address += chunk_size as u64;
        }

        Ok(())
    }

    fn read_memory(&self, processid: u64, startaddress: u64, bytestoread: &mut [u8]) -> Result<()> {
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

    fn write_memory(&self, processid: u64, startaddress: u64, bytestowrite: &[u8]) -> Result<()> {
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
