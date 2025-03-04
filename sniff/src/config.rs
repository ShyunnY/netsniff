use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io,
    path::Path,
    str::FromStr,
};

use anyhow::{anyhow, Result};
use serde::Deserialize;
use sniff_common::Flow;

use crate::{network, util};

#[derive(Debug, Deserialize)]
pub struct Traffic {
    #[serde(
        rename(deserialize = "exportInterval"),
        default = "default_export_interval"
    )]
    pub export_interval: String,

    #[serde(rename(deserialize = "constLabels"))]
    pub const_labels: Option<Vec<String>>,

    #[serde(rename(deserialize = "rules"))]
    pub rules: Option<Vec<ConfigItem>>,
}

impl Traffic {
    pub fn load_config_path<P>(path: P) -> Result<Self>
    where
        P: AsRef<Path>,
    {
        Self::load_config(File::options().read(true).open(path.as_ref())?)
    }

    pub fn load_config<R>(reader: R) -> Result<Self>
    where
        R: io::Read,
    {
        let mut traffic: Self = serde_yaml::from_reader(reader)?;
        traffic.check()?;

        Ok(traffic)
    }

    pub fn check(&mut self) -> Result<()> {
        match self.rules.as_ref() {
            Some(_) => self.check_config(),
            None => Ok(()),
        }
    }

    fn check_config<'a>(&'a mut self) -> Result<()> {
        let config = self.rules.as_mut().unwrap();
        let mut lookup_iface: HashSet<&'a str> = HashSet::new();
        let labels_map: HashSet<String> = if let Some(labels) = &self.const_labels {
            labels.iter().map(|k| k.to_owned()).collect()
        } else {
            HashSet::new()
        };

        for item in config.iter_mut() {
            // check if the network interface exists
            if let Some(ifaces) = item.in_iface.as_ref() {
                ifaces.iter().for_each(|i| {
                    lookup_iface.insert(i);
                });
            }
            if let Some(ifaces) = item.out_iface.as_ref() {
                ifaces.iter().for_each(|i| {
                    lookup_iface.insert(i);
                });
            }

            // check if the cidr validate
            if let Some(cidrs) = item.cidrs.as_ref() {
                for cidr in cidrs {
                    match ipnetwork::Ipv4Network::from_str(cidr) {
                        Ok(ipv4) => {
                            if ipv4.prefix() == 0x20 {
                                return Err(anyhow!(
                                    "current cidr: '{}' mask='{}', please provide a valid mask value",
                                    cidr,
                                    ipv4.mask()
                                ));
                            }
                        }
                        Err(e) => return Err(anyhow!("failed to parse cidr='{}' by {}", cidr, e)),
                    }
                }
            }

            // checks if the rule instance matches constLabel
            // several situations:
            // + Exists in constLabel but not in constValues, in this case we set values ​​to unset
            // + Does not exist in constLabel but exists in constValues, in this case we panic
            // + Part of constValues ​​exists, in this case we add unset to values
            if let Some(values_map) = &item.const_values {
                for (k, _) in values_map {
                    if (!labels_map.is_empty() && !labels_map.contains(k))
                        || (labels_map.is_empty() && !values_map.is_empty())
                    {
                        return Err(anyhow!(
                            "label={} in the '{}' rule does not match that in constLabels or constLabels is empty",
                            k,
                            item.name
                        ));
                    }
                }
            } else {
                let mut empty_values = HashMap::with_capacity(labels_map.capacity());
                for k in labels_map.iter() {
                    empty_values.insert(k.to_owned(), "unset".to_string());
                }
                item.const_values.replace(empty_values);
            };
            let mut replenish = HashMap::new();
            for k in labels_map.iter() {
                if let None = item.const_values.as_ref().unwrap().get(k) {
                    replenish.insert(k.to_owned(), "unset".to_string());
                }
            }
            item.const_values.as_mut().unwrap().extend(replenish);
        }
        util::lookup_interface(lookup_iface)?;

        Ok(())
    }

    pub fn const_labels(&self) -> Vec<String> {
        match &self.const_labels {
            Some(v) => v.clone(),
            None => vec![],
        }
    }
}

// By default, the collector is flushed every 30 seconds.
fn default_export_interval() -> String {
    String::from("30s")
}

type OptionVec<T> = Option<Vec<T>>;

#[derive(Debug, Deserialize)]
pub struct ConfigItem {
    pub name: String,

    #[serde(default)]
    pub protocol: network::Proto,

    pub in_ports: OptionVec<u16>,

    pub cidrs: OptionVec<String>,

    #[serde(rename(deserialize = "inIface"))]
    pub in_iface: OptionVec<String>,

    #[serde(rename(deserialize = "outIface"))]
    pub out_iface: OptionVec<String>,

    #[serde(rename(deserialize = "constValues"))]
    pub const_values: Option<HashMap<String, String>>,
}

impl ConfigItem {
    pub fn bind_flow(&self) -> Flow {
        if self.in_iface.is_some() && self.out_iface.is_some() {
            Flow::All
        } else if self.in_iface.is_some() {
            Flow::Ingress
        } else if self.out_iface.is_some() {
            Flow::Egress
        } else {
            Flow::All
        }
    }
}

#[cfg(test)]
mod test {
    use std::io::Cursor;

    use super::Traffic;

    #[test]
    fn test_load_config() {
        let config_str = r#"
constLabels:
    - name
    - age
rules:
  - name: first
    protocol: tcp
    # check ok
    cidrs:
      - "1.0.0.0/24"
      - "2.3.0.0/16"
    constValues:
      name: l3
      age: l2
    # check
    in_ports:
      - 8080
      - 7070
    in_iface: [lo]
    out_iface: [lo]
"#;

        let reader = Cursor::new(config_str);
        let result = Traffic::load_config(reader);
        assert!(result.is_ok())
    }
}
