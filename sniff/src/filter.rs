use std::{collections::{HashMap, HashSet}, sync::Arc};

use sniff_common::Flow;

use crate::{
    config::ConfigItem,
    network::{NetworkPacket, Proto},
};

#[derive(Debug, Default, Clone)]
pub struct Filter {
    name: String,
    pub protocol: Proto,
    pub in_port_filter: HashSet<u16>,
    pub in_iface_filter: HashSet<String>,
    pub out_iface_filter: HashSet<String>,
    pub label_values: Arc<HashMap<String, String>>,
}

impl From<ConfigItem> for Filter {
    fn from(value: ConfigItem) -> Self {
        let in_port_filter = if let Some(ports) = value.in_ports {
            ports.into_iter().collect()
        } else {
            HashSet::new()
        };

        let in_iface_filter = if let Some(ifaces) = value.in_iface {
            ifaces.into_iter().collect()
        } else {
            HashSet::new()
        };

        let out_iface_filter = if let Some(ifaces) = value.out_iface {
            ifaces.into_iter().collect()
        } else {
            HashSet::new()
        };

        let label_values = if let Some(lv) = value.const_values {
            Arc::new(lv)
        } else {
            Arc::new(HashMap::new())
        };

        Self {
            name: value.name,
            protocol: value.protocol,
            in_port_filter,
            in_iface_filter,
            out_iface_filter,
            label_values,
        }
    }
}


impl Filter {
    pub fn filter(&self, pkt: &NetworkPacket) -> (bool, Option<&HashMap<String, String>>) {
        if !self.match_iface(&pkt.iface, &pkt.flow) {
            return (false, None);
        }

        if !self.match_port(pkt.pkt.dst, &pkt.flow) {
            return (false, None);
        }

        // TODO: add more matching rules
        (true, None)
    }

    pub fn rule_name(&self) -> String {
        self.name.to_owned()
    }

    fn match_iface(&self, iface: &String, flow: &Flow) -> bool {
        match flow {
            Flow::Ingress => {
                if self.in_iface_filter.is_empty() {
                    false
                } else {
                    self.in_iface_filter.contains(iface)
                }
            }
            Flow::Egress => {
                if self.out_iface_filter.is_empty() {
                    false
                } else {
                    self.out_iface_filter.contains(iface)
                }
            }
            /* shouldn't go to this branch. */
            Flow::All => true,
        }
    }

    fn match_port(&self, port: u16, flow: &Flow) -> bool {
        match flow {
            Flow::Ingress => !self.enable_port() || self.in_port_filter.contains(&port),
            Flow::Egress => true,
            /* shouldn't go to this branch. */
            Flow::All => true,
        }
    }

    pub fn enable_port(&self) -> bool {
        self.in_port_filter.len() != 0
    }
}
