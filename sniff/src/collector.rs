use std::{collections::HashMap, path::PathBuf, sync::Arc, time::Duration};

use log::debug;
use network_types::ip::IpProto;
use sniff_common::Flow;

use crate::{
    filter::Filter,
    metrics,
    network::{NetworkPacket, Proto},
};

type DataMap = HashMap<String, PacketCollector>;

/// Collects the network packet size for each rule
#[derive(Debug)]
pub struct CollectorMap {
    export_interval: Duration,
    packet_data: DataMap,

    export_file: PathBuf,
}

#[derive(Debug)]
struct PtrU128(*mut u64);

unsafe impl Send for PtrU128 {}
unsafe impl Sync for PtrU128 {}

#[derive(Debug)]
struct PacketCollector {
    data_total: PtrU128,
    label_values: Option<Arc<HashMap<String, String>>>,
}

impl PacketCollector {
    pub fn new(label_values: Option<Arc<HashMap<String, String>>>) -> Self {
        Self {
            data_total: PtrU128(Box::into_raw(Box::new(0u64))),
            label_values,
        }
    }

    pub fn set(&self, data_tol: u16) {
        unsafe {
            let current = std::ptr::read(self.data_total.0);
            std::ptr::write(self.data_total.0, current.wrapping_add(data_tol as u64));
        }
    }

    pub fn clear(&self) {
        unsafe {
            std::ptr::write(self.data_total.0, 0);
        }
    }

    pub fn get(&self) -> u64 {
        unsafe { std::ptr::read(self.data_total.0) }
    }
}

impl CollectorMap {
    pub fn new(internal: Duration, export_file: PathBuf) -> Self {
        Self {
            export_interval: internal,
            packet_data: HashMap::new(),
            export_file,
        }
    }

    pub fn insert(&mut self, name: String, label_values: Option<Arc<HashMap<String, String>>>) {
        self.packet_data
            .insert(name, PacketCollector::new(label_values));
    }

    pub fn add(&self, name: &String, data_tol: u16) {
        if let Some(c) = self.packet_data.get(name) {
            c.set(data_tol);
        }
    }

    pub async fn flush(&self) {
        let mut tick = tokio::time::interval(self.export_interval);
        loop {
            tick.tick().await;
            debug!("trigger collector flush to metrics cycle");

            self.packet_data.iter().for_each(|(identity_line, item)| {
                let mut meta_kvs = identity_to_label_values(identity_line);
                if let Some(label_values) = &item.label_values {
                    label_values.iter().for_each(|(k, v)| {
                        meta_kvs.insert(k.as_str(), v.as_str());
                    });
                };

                metrics::set_counter(item.get(), &meta_kvs);
                item.clear();
            });
            metrics::flush_file(&self.export_file).await;
        }
    }
}

pub fn identity_to_label_values(identity_line: &str) -> HashMap<&str, &str> {
    let values: Vec<&str> = identity_line.split("_").collect();
    let mut result = HashMap::with_capacity(metrics::PACKET_TOL_LV_CAP);

    result.insert("rule", values[0]);
    result.insert("traffic", values[1]);
    result.insert("protocol", values[2]);
    result.insert("iface", values[3]);

    result
}

/// Converts a [NetworkPacket] to an Identity unique identifier.
///
/// This function is mainly used to find its [PacketCollector] in [Collector].
/// For more information, see [filter_to_identity]
pub fn netpkt_to_identity(
    rule_name: &String,
    enable_port: bool,
    net_pkt: &NetworkPacket,
) -> String {
    let (traffic, port) = match &net_pkt.flow {
        Flow::Ingress => ("in", {
            if enable_port {
                net_pkt.pkt.dst.to_string()
            } else {
                "undefine".to_string()
            }
        }),
        Flow::Egress => ("out", "unsupport".to_string()),
        Flow::All => panic!("should be no bidirectional traffic type"),
    };

    let proto = match &net_pkt.pkt.proto {
        IpProto::Tcp => "tcp",
        IpProto::Udp => "udp",
        _ => panic!(
            "protocol is currently not supported: {:?}",
            &net_pkt.pkt.proto
        ),
    };

    format!(
        "{}_{}_{}_{}_{}",
        rule_name, traffic, proto, &net_pkt.iface, port
    )
}

/// Convert filter to Identity string identifier.
/// `rule_name`` is unique, so we can combine rule_name with traffic direction, protocol, port, etc. to form a unique identifier.
///
/// The unique identifier can offload a lot of metadata to find its associated [PacketCollector] in [Collector]
///
/// * format it follows is: `<rule_name>_<flow>_<protocol>_<iface>_<port>`
/// * final effect demo is as follows: `demo1_ingress_tcp_enp1s0_undefine`
pub fn filter_to_identity(filter: &Filter) -> Vec<String> {
    let mut identitys = Vec::new();

    let must_proto = match filter.protocol {
        Proto::TCP => vec!["tcp"],
        Proto::UDP => vec!["udp"],
        Proto::ALL => vec!["tcp", "udp"],
    };

    for iface in &filter.in_iface_filter {
        if !filter.in_port_filter.is_empty() {
            for port in &filter.in_port_filter {
                for proto in &must_proto {
                    identitys.push(format!(
                        "{}_{}_{}_{}_{}",
                        filter.rule_name(),
                        "in",
                        proto,
                        iface,
                        port
                    ));
                }
            }
        } else {
            for proto in &must_proto {
                identitys.push(format!(
                    "{}_{}_{}_{}_{}",
                    filter.rule_name(),
                    "in",
                    proto,
                    iface,
                    "undefine"
                ));
            }
        }
    }

    for iface in &filter.out_iface_filter {
        for proto in &must_proto {
            identitys.push(format!(
                "{}_{}_{}_{}_{}",
                filter.rule_name(),
                "out",
                proto,
                iface,
                "unsupport",
            ));
        }
    }

    identitys
}
