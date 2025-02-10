use core::mem;

use aya_ebpf::programs::TcContext;
use sniff_common::RawPacket;

use crate::map::PACKET_DATA;

/// Used to indicate the traffic protocol of the detection, with the following conventions:
/// * 0: ALL
/// * 1: TCP
/// * 2: UDP
#[no_mangle]
static SNIFF_PROTOCOL: i32 = 0;

#[inline]
pub fn ptr_at<T>(ctx: &TcContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[inline]
pub fn submit(pkt: RawPacket) {
    if let Some(mut rb) = { PACKET_DATA.reserve(0) } {
        unsafe { (*rb.as_mut_ptr()) = pkt };
        rb.submit(0);
    }
}

#[inline]
pub fn is_tcp() -> bool {
    let sniff_protocol = unsafe { core::ptr::read_volatile(&SNIFF_PROTOCOL) };

    sniff_protocol == 0 || sniff_protocol == 1
}

#[inline]
pub fn is_udp() -> bool {
    let sniff_protocol = unsafe { core::ptr::read_volatile(&SNIFF_PROTOCOL) };

    sniff_protocol == 0 || sniff_protocol == 2
}
