use std::collections::{HashMap, HashSet};

use sniff_common::Flow;

use crate::{config::ConfigItem, network::NetworkPacket};

#[derive(Debug, Default,Clone)]
pub struct Filter {
    pub name: String,
    pub port_filter: HashSet<u16>,
    pub in_iface_filter: HashSet<String>,
    pub out_iface_filter: HashSet<String>,
    pub label_values: HashMap<String, String>,
}

impl From<ConfigItem> for Filter {
    fn from(value: ConfigItem) -> Self {
        let port_filter = if let Some(ports) = value.ports {
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

        let label_values = if let Some(lv) = value.label_values {
            lv
        } else {
            HashMap::new()
        };

        Self {
            name: value.name,
            port_filter,
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

        (true, None)
    }

    fn match_iface(&self, iface: &String, flow: &Flow) -> bool {
        match flow {
            Flow::Ingress => {
                if self.in_iface_filter.is_empty() {
                    true
                } else {
                    self.in_iface_filter.contains(iface)
                }
            }
            Flow::Egress => {
                if self.out_iface_filter.is_empty() {
                    true
                } else {
                    self.out_iface_filter.contains(iface)
                }
            }
            /* shouldn't go to this branch. */
            Flow::All => true,
        }
    }
}
