use aya::{
    include_bytes_aligned,
    maps::RingBuf,
    programs::{tc, SchedClassifier},
    EbpfLoader,
};
use libc::{self, c_int};
use log::{error, info};
use sniff_common::RawPacket;
use tokio::{
    io::{unix::AsyncFd, Interest},
    sync::mpsc,
};

use crate::network::Packet;

pub async fn load_ingress_sched_cls(iface: String, proto: i32, _tx: Option<mpsc::Sender<()>>) {
    let ret = set_rlimit();
    if ret != 0 {
        error!("remove limit on locked memory failed, ret is: {}", ret);
    }

    let mut ebpf = match EbpfLoader::new()
        .set_global("SNIFF_PROTOCOL", &proto, true)
        .load(include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/",
            env!("CARGO_PKG_NAME"),
        ))) {
        Ok(ebpf) => ebpf,
        Err(e) => {
            println!("{}", e);
            error!(
                "failed to load the ingress eBPF program(TC) bytecode by error: {}",
                e
            );
            return;
        }
    };
    let _ = tc::qdisc_add_clsact(&iface);
    let prog: &mut SchedClassifier = ebpf.program_mut("sniff").unwrap().try_into().unwrap();
    if let Err(e) = prog.load() {
        error!(
            "failed to load the ingress eBPF program(TC) to the kernal by error: {}",
            e
        );
        return;
    };

    if let Err(e) = prog.attach(&iface, tc::TcAttachType::Ingress) {
        error!(
            "failed to attach the ingress eBPF program(TC) to the {} network interface by error: {}",
            iface,
            e
        );
        return;
    } else {
        info!(
            "suceess to attach the ingress eBPF program(TC) to the {} network interface!",
            iface
        );
    }

    let map = match RingBuf::try_from(ebpf.map_mut("PACKET_DATA").unwrap()) {
        Ok(map) => map,
        Err(e) => {
            error!(
                "failed to load the ingress eBPF program(TC) RingBuf by error: {}",
                e
            );
            return;
        }
    };

    let mut fd = AsyncFd::new(map).unwrap();
    loop {
        let mut guard = fd.ready_mut(Interest::READABLE).await.unwrap();
        let ring_buf = guard.get_inner_mut();
        while let Some(raw_pkt) = ring_buf.next() {
            let raw_pkt: [u8; RawPacket::LEN] = raw_pkt.to_owned().try_into().unwrap();
            let packet: Packet = raw_pkt.into();

            println!("{}", packet);
        }
        guard.clear_ready();
    }
}

fn set_rlimit() -> c_int {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };

    unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) }
}
