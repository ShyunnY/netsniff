use std::collections::{HashMap, HashSet};

use anyhow::{anyhow, Ok, Result};
use sniff_common::Flow;

use crate::{config::ConfigItem, network::NetworkPacket};

#[derive(Debug, Default, Clone)]
pub struct Filter {
    name: String,
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

pub fn convert_line_identity(
    flow: Flow,
    rule_name: &String,
    iface: &String,
    mut port: String,
) -> String {
    let traffic = match flow {
        Flow::Ingress => "ingress",
        Flow::Egress => {
            port = "undefine".to_string();
            "egress"
        }
        Flow::All => {
            /* this branch should not be executed */
            ""
        }
    };

    format!("{}_{}_{}_{}", traffic, rule_name, iface, port)
}

pub fn convert_identity_map<'a>(line: &'a String) -> Result<HashMap<&'a str, &'a str>> {
    if line.len() == 0 {
        return Err(anyhow!("identity line is empty!"));
    }
    let vals: Vec<&str> = line.split("_").collect();
    let mut map = HashMap::with_capacity(4);

    map.insert("traffic", vals[0]);
    map.insert("rule_name", vals[1]);
    map.insert("iface", vals[2]);
    map.insert("port", vals[3]);

    Ok(map)
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

    pub fn identifier(&self) -> Vec<String> {
        let mut idents = Vec::new();
        for iface in &self.in_iface_filter {
            if self.port_filter.len() > 0 {
                for port in &self.port_filter {
                    let line = format!("ingress_{}_{}_{}", &self.name, iface, port);
                    idents.push(line);
                }
            } else {
                let line = format!("ingress_{}_{}_undefine", &self.name, iface);
                idents.push(line);
            }
        }

        for iface in &self.out_iface_filter {
            let line = format!("egress_{}_{}_undefine", &self.name, iface);
            idents.push(line);
        }

        idents
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
            Flow::Ingress => !self.enable_port() || self.port_filter.contains(&port),
            Flow::Egress => true,
            /* shouldn't go to this branch. */
            Flow::All => true,
        }
    }

    pub fn enable_port(&self) -> bool {
        self.port_filter.len() != 0
    }
}
