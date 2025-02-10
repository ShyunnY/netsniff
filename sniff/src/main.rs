use sniff::ebpf;

#[tokio::main]
async fn main() {
    tokio::spawn(async {
        ebpf::load_ingress_sched_cls("enp1s0".to_string(), 0, None).await;
    });

    loop {}
}
