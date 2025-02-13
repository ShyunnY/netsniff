pub mod config;
pub mod app;
pub mod cidr;
pub mod cmd;
pub mod ebpf;
pub mod network;

pub mod util{
    use std::{
        ffi::{c_char, CStr},
        io,
    };

    pub fn uname() -> io::Result<SysInfo> {
        let mut buf = unsafe { std::mem::zeroed() };
        match unsafe { libc::uname(&mut buf) } {
            0 => Ok(SysInfo::from(buf)),
            _ => Err(io::Error::last_os_error()),
        }
    }
    
    #[derive(Debug)]
    pub struct SysInfo {
        pub sys_name: String,
        pub node_name: String,
        pub release: String,
        pub version: String,
    }
    
    impl From<libc::utsname> for SysInfo {
        fn from(value: libc::utsname) -> Self {
            Self {
                sys_name: cstr(&value.sysname[..]).to_string_lossy().to_string(),
                node_name: cstr(&value.nodename[..]).to_string_lossy().to_string(),
                release: cstr(&value.release[..]).to_string_lossy().to_string(),
                version: cstr(&value.version[..]).to_string_lossy().to_string(),
            }
        }
    }
    
    #[inline]
    fn cstr(buf: &[c_char]) -> &CStr {
        unsafe { CStr::from_ptr(buf.as_ptr()) }
    }
}
