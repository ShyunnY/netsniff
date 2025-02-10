use std::fmt::Debug;

use ipnetwork::IpNetwork;

#[derive(Debug)]
struct Node<N> {
    metadata: N,

    is_last: bool,
    left: Option<Box<Node<N>>>,
    right: Option<Box<Node<N>>>,
}

impl<N: Default> Default for Node<N> {
    fn default() -> Self {
        Self {
            metadata: N::default(),
            is_last: false,
            left: None,
            right: None,
        }
    }
}

#[derive(Debug)]
pub struct PrefixTree<N> {
    root: Option<Box<Node<N>>>,
}

impl<N> PrefixTree<N>
where
    N: Default + Copy + Clone + Debug,
{
    const BIT_0: u8 = 48;
    const BIT_1: u8 = 49;

    pub fn new() -> Self {
        PrefixTree {
            root: Some(Box::new(Node::default())),
        }
    }

    pub fn insert(&mut self, addr: ipnetwork::Ipv4Network, metadata: N) {
        let mut tmp = self
            .root
            .as_mut()
            .expect("PrefixTree is currently not initialized");

        let bin = ipaddr_to_binary(addr);
        for i in 0..bin.len() {
            if let Some(b) = bin.get(i) {
                if *b == Self::BIT_1 {
                    if tmp.right.is_none() {
                        tmp.right = Some(Box::new(Node::default()));
                    }
                    tmp = tmp.right.as_mut().unwrap();
                }
                if *b == Self::BIT_0 {
                    if tmp.left.is_none() {
                        tmp.left = Some(Box::new(Node::default()));
                    }
                    tmp = tmp.left.as_mut().unwrap();
                }
            }

            if i == bin.len() - 1 {
                (tmp.is_last, tmp.metadata) = (true, metadata)
            }
        }
    }

    pub fn search<T>(&self, addr: T) -> (bool, N)
    where
        T: Into<IpNetwork>,
    {
        let bin = ipaddr_to_binary(addr);
        if self.root.is_none() {
            return (false, N::default());
        }

        let mut tmp = self.root.as_ref();
        let mut assume_last = None;
        for b in bin {
            if b == Self::BIT_1 {
                tmp = tmp.unwrap().right.as_ref();
            }
            if b == Self::BIT_0 {
                tmp = tmp.unwrap().left.as_ref();
            }

            if tmp.is_none() {
                break;
            }

            let node = tmp.unwrap();
            if node.is_last {
                assume_last = Some(node);
            }
        }

        if let Some(node) = assume_last {
            (node.is_last, node.metadata)
        } else {
            (false, N::default())
        }
    }
}

#[inline]
fn ipaddr_to_binary<T>(cidr: T) -> Vec<u8>
where
    T: Into<ipnetwork::IpNetwork>,
{
    let ip_network: ipnetwork::IpNetwork = cidr.into();
    let sub_cidr = match ip_network.network() {
        std::net::IpAddr::V4(ipv4_addr) => {
            let mut binary_ip = ipv4_addr
                .octets()
                .iter()
                .map(|&octet| format!("{:08b}", octet))
                .collect::<String>();
            binary_ip.truncate(ip_network.prefix() as usize);

            binary_ip
        }
        _ => String::default(),
    };

    sub_cidr.into_bytes()
}

#[cfg(test)]
mod test {
    use std::{net::IpAddr, str::FromStr};

    use ipnetwork::Ipv4Network;

    use super::PrefixTree;

    #[test]
    fn test_simple_prefix_trie() {
        let mut trie = PrefixTree::<i32>::new();
        trie.insert(Ipv4Network::from_str("1.0.1.0/16").unwrap(), 101);
        trie.insert(Ipv4Network::from_str("1.1.1.0/24").unwrap(), 102);
        trie.insert(Ipv4Network::from_str("2.0.0.0/8").unwrap(), 103);
        trie.insert(Ipv4Network::from_str("2.0.0.0/24").unwrap(), 104);

        assert_eq!(
            trie.search(IpAddr::from_str("1.0.134.168").unwrap()),
            (true, 101)
        );
        assert_eq!(
            trie.search(IpAddr::from_str("1.1.1.254").unwrap()),
            (true, 102)
        );
        assert_eq!(
            trie.search(IpAddr::from_str("2.0.1.168").unwrap()),
            (true, 103)
        );
        assert_eq!(
            trie.search(IpAddr::from_str("2.0.0.168").unwrap()),
            (true, 104)
        );
    }
}
