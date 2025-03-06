use std::{fmt::Debug, net::Ipv4Addr, sync::Arc};

use ipnetwork::{IpNetwork, Ipv4Network};
use log::debug;

#[derive(Debug)]
struct Node<N> {
    metadata: Arc<N>,

    is_last: bool,
    left: Option<Box<Node<N>>>,
    right: Option<Box<Node<N>>>,
}

impl<N: Default> Default for Node<N> {
    fn default() -> Self {
        Self {
            metadata: Arc::new(N::default()),
            is_last: false,
            left: None,
            right: None,
        }
    }
}

impl<N> Node<N> {
    pub fn empty(&self) -> bool {
        self.left.is_none() && self.right.is_none()
    }
}

#[derive(Debug)]
pub struct PrefixTree<N> {
    match_all: bool,
    root: Option<Box<Node<N>>>,
}

impl<N> Default for PrefixTree<N>
where
    N: Default + Clone + Debug,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<N> PrefixTree<N>
where
    N: Default + Clone + Debug,
{
    const BIT_0: u8 = 48;
    const BIT_1: u8 = 49;

    pub fn new() -> Self {
        PrefixTree {
            match_all: false,
            root: Some(Box::new(Node::default())),
        }
    }

    pub fn empty(&self) -> bool {
        self.root.is_none() || self.root.as_ref().unwrap().empty()
    }

    pub fn set_match_all(&mut self) {
        self.match_all = true
    }

    pub fn match_all(&self) -> bool {
        self.match_all
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
                (tmp.is_last, tmp.metadata) = (true, Arc::new(metadata.clone()))
            }
        }
    }

    pub fn search<T>(&self, addr: T) -> (bool, Arc<N>)
    where
        T: Into<IpNetwork>,
    {
        let bin = ipaddr_to_binary(addr);
        if self.root.is_none() {
            return (false, Arc::new(N::default()));
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
            (node.is_last, node.metadata.clone())
        } else {
            (self.match_all, Arc::new(N::default()))
        }
    }

    /// Used to report the cidr items of PrefixTree mounts
    pub fn summary(&self) {
        if let Some(root) = self.root.as_deref() {
            let mut path = Vec::new();
            self.dfs(root, &mut path);
        }
    }

    fn dfs(&self, node: &Node<N>, path: &mut Vec<u8>) {
        if node.is_last {
            // todo: generic N requires 'Display' trait bound?
            debug!(
                "{} => {:?}",
                binary_to_cidr(path).to_string(),
                node.metadata
            );
        }

        if let Some(left) = node.left.as_ref() {
            path.push(Self::BIT_0);
            self.dfs(left, path);
            path.pop();
        }

        if let Some(right) = node.right.as_ref() {
            path.push(Self::BIT_1);
            self.dfs(right, path);
            path.pop();
        }
    }
}

// Convert a cidr address to a binary slice
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

// Convert a binary slice to a cidr address
#[inline]
fn binary_to_cidr(bin: &[u8]) -> Ipv4Network {
    let bits = bin.len();
    let mask = bits as u8; // length represents the mask

    let mut cidr_vec: Vec<u8> = Vec::with_capacity(32);
    for i in 0..32 {
        if i >= bits {
            // when the cidr address segment is less than 32 bits,
            // we fill it with zeros.
            cidr_vec.push(48);
        } else {
            cidr_vec.push(bin[i]);
        }
    }

    // convert the four ranges of the IP address into decimal
    let mut cidr = [0u8; 5];
    for interval in 0..4 {
        let mut decimal = 0;
        for i in 0..8 {
            let index = 8 - i - 1;
            decimal += (cidr_vec[interval * 8 + i] & 0xf) << index;
        }
        cidr[interval] = decimal;
    }
    cidr[4] = mask;

    Ipv4Network::new(Ipv4Addr::new(cidr[0], cidr[1], cidr[2], cidr[3]), cidr[4]).unwrap()
}

#[cfg(test)]
mod test {
    use std::{net::IpAddr, str::FromStr, sync::Arc};

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
            (true, Arc::new(101))
        );
        assert_eq!(
            trie.search(IpAddr::from_str("1.1.1.254").unwrap()),
            (true, Arc::new(102))
        );
        assert_eq!(
            trie.search(IpAddr::from_str("2.0.1.168").unwrap()),
            (true, Arc::new(103))
        );
        assert_eq!(
            trie.search(IpAddr::from_str("2.0.0.168").unwrap()),
            (true, Arc::new(104))
        );
    }

    #[test]
    fn test_match_all_prefix_trie() {
        let no_match_trie = PrefixTree::<()>::new();
        assert_eq!(
            no_match_trie.search(IpAddr::from_str("1.0.0.168").unwrap()),
            (false, Arc::new(()))
        );
        assert_eq!(
            no_match_trie.search(IpAddr::from_str("2.0.0.168").unwrap()),
            (false, Arc::new(()))
        );

        let mut match_trie = PrefixTree::<()>::new();
        match_trie.set_match_all();
        assert_eq!(
            match_trie.search(IpAddr::from_str("1.0.0.168").unwrap()),
            (true, Arc::new(()))
        );
        assert_eq!(
            match_trie.search(IpAddr::from_str("2.0.0.168").unwrap()),
            (true, Arc::new(()))
        );
    }
}
