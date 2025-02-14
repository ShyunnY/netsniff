use std::{collections::{HashMap, HashSet}, io, str::FromStr};

use anyhow::{anyhow, Result};
use serde::Deserialize;

use crate::{network, util};

#[derive(Debug, Deserialize)]
struct Traffic {
    #[serde(rename(deserialize = "trafficConfig"))]
    pub traffic_config: Option<Vec<ConfigItem>>,
}

impl Traffic {
    pub fn load_config<R>(reader: R) -> Result<Self>
    where R: io::Read{
        let traffic: Self = serde_yaml::from_reader(reader)?;
        traffic.check()?;

        Ok(traffic)
    }

    pub fn check(&self) -> Result<()> {
        match self.traffic_config.as_ref() {
            Some(_) => self.check_config(),
            None => Ok(()),
        }
    }

    pub fn check_config<'a>(&'a self) -> Result<()> {
        let config = self.traffic_config.as_ref().unwrap();
        let mut lookup_iface: HashSet<&'a str> = HashSet::new();

        for item in config {
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
                        Err(e ) => {
                            return Err(anyhow!("failed to parse cidr='{}' by {}", cidr, e))
                        }
                    }
                }
            }
        }
        util::lookup_interface(lookup_iface)?;

        Ok(())
    }
}

type OptionVec<T> = Option<Vec<T>>;

#[derive(Debug, Deserialize)]
struct ConfigItem {
    name: String,
    #[serde(default)]
    protocol: network::Protol,
    ports: OptionVec<u16>,
    cidrs: OptionVec<String>,
    in_iface: OptionVec<String>,
    out_iface: OptionVec<String>,
    label_values: Option<HashMap<String,String>>
}

#[cfg(test)]
mod test{
    use std::io::Cursor;

    use super::Traffic;

    #[test]
    fn test_load_config(){
        let config_str = r#"
trafficConfig:
  - name: first
    protocol: tcp
    # check ok
    cidrs:
      - "1.0.0.0/24"
      - "2.3.0.0/16"
    # check   
    ports:
      - 8080
      - 7070
    in_iface: [lo]
    out_iface: [lo]
    label_values:
      hello: world        
"#;

    let reader = Cursor::new(config_str);
    let result = Traffic::load_config(reader);

    assert!(result.is_ok())
    }
}