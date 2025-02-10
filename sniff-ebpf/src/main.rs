#![no_std]
#![no_main]

use aya_ebpf::{bindings::TC_ACT_OK, macros::classifier, programs::TcContext};
use aya_log_ebpf::error;

mod map;
mod sniff;
mod util;

#[classifier]
pub fn sniff(ctx: TcContext) -> i32 {
    match sniff::try_sniff(&ctx) {
        Ok(_) => TC_ACT_OK,
        Err(e) => {
            error!(&ctx, "sniff_ingress network pkt by err: {}", e);
            TC_ACT_OK
        }
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
