use std::{collections::HashSet, str::FromStr, sync::Arc};

use clap::Parser;
use ipnetwork::Ipv4Network;
use log::{error, info};
use netsniff::{
    app::Application,
    cidr::PrefixTree,
    cmd::{self, Cmd},
    collector::{self, CollectorMap},
    config::Traffic,
    ebpf,
    filter::Filter,
    metrics,
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
                Ok(mut config) => {
                    config.check()?;

                    // build metrics for data package export
                    if let Err(e) = metrics::build_metrics(config.const_labels()) {
                        error!("failed to build metrics by err {}", e);
                    }
                    let export_internal = humantime::parse_duration(&config.export_interval)?;

                    if let Some(rule) = config.rules {
                        let mut trie = PrefixTree::<Arc<Box<Filter>>>::new();
                        let mut ifaces: HashSet<String> = HashSet::new();
                        let mut flow = 0x3;
                        let mut proto: i32 = 0x3;
                        let mut empty_filter: Vec<Arc<Box<Filter>>> = Vec::new();
                        let mut collector_map = CollectorMap::new(export_internal);

                        for item in rule {
                            proto &= item.protocol as i32;
                            flow &= item.bind_flow() as i32;

                            // only get the intersection of the network interfaces
                            let cidrs = item.cidrs.clone();
                            let filter_item: Filter = item.into();

                            ifaces.extend(filter_item.in_iface_filter.clone());
                            ifaces.extend(filter_item.out_iface_filter.clone());

                            for identity in collector::filter_to_identity(&filter_item) {
                                info!("build metrics identity: [{}]", identity);
                                collector_map.insert(
                                    identity,
                                    if !filter_item.label_values.is_empty() {
                                        Some(filter_item.label_values.clone())
                                    } else {
                                        None
                                    },
                                );
                            }

                            let filter: Arc<Box<Filter>> = Arc::new(Box::new(filter_item));
                            match cidrs {
                                Some(cidrs) if !cidrs.is_empty() => {
                                    /* handler non-empty filters */
                                    for cidr in cidrs {
                                        trie.insert(
                                            Ipv4Network::from_str(cidr.as_ref())?,
                                            filter.clone(),
                                        );
                                    }
                                }
                                _ => {
                                    /* handler empty filters */
                                    empty_filter.push(filter);
                                }
                            }
                        }

                        let mut application = Application::new(
                            ifaces.into_iter().collect(),
                            trie,
                            Some(empty_filter),
                            Some(collector_map),
                        );
                        tokio::spawn(async move { application.run(proto, flow.into()).await });
                    }
                }
                Err(e) => {
                    error!("failed to load config '{}' by err {}", &run.config, e);
                    std::process::exit(1);
                }
            }
        }
        cmd::SubCmd::Tcp | cmd::SubCmd::Udp | cmd::SubCmd::All => {
            // TODO: handler empty filter case
            info!("read configuration from a command flag");
            let ifaces = get_cmd_ifaces(&command);
            let proto = command.sub_cmd.proto_num();
            let trie = if !command.cidrs.is_empty() {
                let mut trie = PrefixTree::new();
                let empty_filter = Arc::new(Box::new(Filter::default_pass_filter()));
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
                let mut trie = PrefixTree::<Arc<Box<Filter>>>::new();
                trie.set_match_all();

                trie
            };

            let flow = match command.flow {
                cmd::Flow::Ingress => sniff_common::Flow::Ingress,
                cmd::Flow::Egress => sniff_common::Flow::Egress,
                cmd::Flow::All => sniff_common::Flow::All,
            };

            let mut application = Application::new(ifaces.into_iter().collect(), trie, None, None);
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
    if command.ifaces.is_empty() {
        error!("must specify at least one network interface to which Sniff is attached.");
        std::process::exit(1);
    }

    for iface in &command.ifaces {
        ifaces.insert(iface.to_owned());
    }

    ifaces
}
