use std::{collections::HashSet, str::FromStr, sync::Arc};

use clap::Parser;
use ipnetwork::Ipv4Network;
use log::{error, info};
use sniff::{
    app::Application,
    cidr::PrefixTree,
    cmd::{self, Cmd},
    config::Traffic,
    ebpf,
    filter::Filter,
};
use tokio::signal;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let command = Cmd::parse();
    setup(&command);

    match command.sub_cmd {
        cmd::SubCmd::Check => {
            let ifaces = get_cmd_ifaces(&command);
            for iface in ifaces.iter() {
                ebpf::check_attach(iface.to_owned(), sniff_common::Flow::Ingress);
                ebpf::check_attach(iface.to_owned(), sniff_common::Flow::Egress);
            }
            return Ok(());
        }
        cmd::SubCmd::Run(run) => {
            info!("read configuration from a config file");
            match Traffic::load_config_path(&run.config) {
                Ok(config) => {
                    config.check()?;

                    if let Some(c) = config.traffic_config {
                        let mut trie = PrefixTree::<Arc<Box<Filter>>>::new();
                        let mut ifaces: HashSet<String> = HashSet::new();
                        let mut flow = 0x3;
                        let mut proto: i32 = 0x3;
                        let mut empty_filter: Vec<Arc<Box<Filter>>> = Vec::new();
                        for item in c {
                            proto &= item.protocol as i32;
                            flow &= item.bind_flow() as i32;

                            // only get the intersection of the network interfaces
                            let cidrs = item.cidrs.clone();
                            let filter_item: Filter = item.into();
                            ifaces.extend(filter_item.in_iface_filter.clone());
                            ifaces.extend(filter_item.out_iface_filter.clone());

                            let filter: Arc<Box<Filter>> = Arc::new(Box::new(filter_item));
                            match cidrs {
                                Some(cidrs) if cidrs.len() != 0 => {
                                    /* handler non-empty */
                                    for cidr in cidrs {
                                        trie.insert(
                                            Ipv4Network::from_str(cidr.as_ref())?,
                                            filter.clone(),
                                        );
                                    }
                                }
                                _ => {
                                    /* handler empty */
                                    empty_filter.push(filter);
                                }
                            }
                        }

                        let mut application =
                            Application::new(ifaces.into_iter().collect(), trie, Some(empty_filter));
                        tokio::spawn(async move { application.run(proto, flow.into()).await });
                    }
                }
                Err(e) => {
                    error!("failed to load config '{}' by err {}", &run.config, e);
                    std::process::exit(1);
                }
            }
        }
        _ => {
            info!("read configuration from a command flag");
            let ifaces = get_cmd_ifaces(&command);
            let proto = command.sub_cmd.proto_num();
            let trie = if command.cidrs.len() != 0 {
                let mut trie = PrefixTree::new();
                let empty_filter = Arc::new(Box::new(Filter::default()));
                for cidr in command.cidrs.iter() {
                    match ipnetwork::Ipv4Network::from_str(cidr) {
                        Ok(addr) => {
                            trie.insert(addr, empty_filter.clone());
                        }
                        Err(e) => {
                            error!("failed to parse {} cidr to ipv4Network by err {}", cidr, e);
                            std::process::exit(1);
                        }
                    };
                }
                trie
            } else {
                PrefixTree::<Arc<Box<Filter>>>::new()
            };

            let flow = match command.flow {
                cmd::Flow::Ingress => sniff_common::Flow::Ingress,
                cmd::Flow::Egress => sniff_common::Flow::Egress,
                cmd::Flow::All => sniff_common::Flow::All,
            };

            let mut application = Application::new(ifaces.into_iter().collect(), trie, None);
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

fn get_cmd_ifaces(command: &Cmd) -> HashSet<String> {
    let mut ifaces = HashSet::new();
    if command.ifaces.len() == 0 {
        error!("must specify at least one network interface to which Sniff is attached.");
        std::process::exit(1);
    }

    for iface in &command.ifaces {
        ifaces.insert(iface.to_owned());
    }

    ifaces
}
