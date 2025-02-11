use std::str::FromStr;

use anyhow::Ok;
use clap::Parser;
use log::{error, info};
use sniff::{
    app::Application,
    cidr::PrefixTree,
    cmd::{self, Cmd},
    ebpf,
};
use tokio::signal;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let command = Cmd::parse();
    setup(&command);

    if command.ifaces.len() == 0 {
        error!("must specify at least one network interface to which Sniff is attached.");
        return Ok(());
    }

    let flow = match command.flow {
        cmd::Flow::Ingress => sniff_common::Flow::Ingress,
        cmd::Flow::Egress => sniff_common::Flow::Egress,
        cmd::Flow::All => sniff_common::Flow::All,
    };
    match command.sub_cmd {
        cmd::SubCmd::Check => {
            for iface in command.ifaces.iter() {
                ebpf::check_attach(iface.to_owned(), sniff_common::Flow::Ingress);
                ebpf::check_attach(iface.to_owned(), sniff_common::Flow::Egress);
            }
            return Ok(());
        }
        _ => {
            let proto = command.sub_cmd as i32;
            let trie = if command.cidrs.len() > 0 {
                let mut trie = PrefixTree::new();
                for cidr in command.cidrs.iter() {
                    let addr = ipnetwork::Ipv4Network::from_str(cidr)?;
                    trie.insert(addr, addr.to_string());
                }
                trie
            } else {
                PrefixTree::new()
            };
            let mut application = Application::new(command.ifaces, trie);

            tokio::spawn(async move { application.run(proto, flow).await });
        }
    };

    if let Err(e) = signal::ctrl_c().await {
        error!("failed to listen SIGINT signal by err: {}", e);
    }
    info!("Sniff program exits normally and detaches the eBPF program");

    Ok(())
}

fn setup(command: &Cmd) {
    env_logger::Builder::from_env(env_logger::Env::new().default_filter_or(&command.verbose))
        .format_module_path(false)
        .init();

    if unsafe { libc::geteuid() } != 0 {
        error!("Sniff program must be run as root!");
        std::process::exit(1);
    }
}
