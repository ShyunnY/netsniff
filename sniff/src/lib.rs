pub mod app;
pub mod cidr;
pub mod cmd;
pub mod collector;
pub mod config;
pub mod ebpf;
pub mod filter;
pub mod metrics;
pub mod network;

pub mod util {
    use std::{
        collections::HashSet,
        ffi::{c_char, CStr},
        io,
    };

    use anyhow::{anyhow, Result};

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

    fn cstr(buf: &[c_char]) -> &CStr {
        unsafe { CStr::from_ptr(buf.as_ptr()) }
    }

    /// lookup whether the given network interface exists on the current host.
    pub fn lookup_interface(iface_set: HashSet<&str>) -> Result<()> {
        let mut result = HashSet::new();
        unsafe {
            let mut iface_addr: *mut libc::ifaddrs = std::ptr::null_mut();
            if libc::getifaddrs(&mut iface_addr) == 0 {
                let mut iface = iface_addr;
                while !iface.is_null() {
                    let ifa_name = (*iface).ifa_name;
                    let ifa_addr = (*iface).ifa_addr;

                    if !ifa_name.is_null() && !ifa_addr.is_null() {
                        let c_interface = CStr::from_ptr(ifa_name);
                        let interface = c_interface.to_str().unwrap();
                        result.insert(interface);
                    }
                    iface = (*iface).ifa_next;
                }
            }
        }
        iface_set.iter().try_for_each(|&i| match result.get(i) {
            Some(_) => Ok(()),
            None => Err(anyhow!(
                "'{}' network interface not exist in current machine",
                i
            )),
        })?;

        Ok(())
    }
}
