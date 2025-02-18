use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(disable_help_subcommand = true)]
pub struct Cmd {
    /// Set the log verbose.
    #[arg(
        short = 'v',
        default_value = "info",
        value_name = "verbose",
        global = true,
        value_parser = ["debug","info","warn","error"]
    )]
    pub verbose: String,

    /// Detected traffic direction
    #[arg(
        short = 'd',
        value_name = "FLOW",
        num_args = 0..=1,
        default_value_t = Flow::All,
        value_enum,
        global = true,
    )]
    pub flow: Flow,

    /// One or more ifaces to attach. (e.g. --iface lo,eth0...)
    #[arg(short = 'i', value_name = "iface,", global = true)]
    pub ifaces: Vec<String>,

    /// Detect traffic matching the given cidr. If not set, all traffic will be matched.
    #[arg(short = 'c', value_name = "cidr,", global = true)]
    pub cidrs: Vec<String>,

    #[command(subcommand)]
    pub sub_cmd: SubCmd,
}

#[derive(ValueEnum, Copy, Clone, Debug, PartialEq, Eq)]
pub enum Flow {
    /// Represents ingress traffic
    Ingress,

    //// Represents egress traffic
    Egress,

    /// Represents all flow traffic
    All,
}

#[derive(Subcommand, Clone)]
pub enum SubCmd {
    /// Detect all types of (TCP/UDP) traffic
    All,

    /// Detect TCP type traffic
    Tcp,

    /// Detect UDP type traffic
    Udp,

    /// Check whether the sniff ebpf program can be mounted correctly
    Check,

    /// Running sniff ebpf program as server
    Run(Run),
}

impl SubCmd {
    pub fn proto_num(&self) -> i32 {
        match self {
            SubCmd::Tcp => 1,
            SubCmd::Udp => 2,
            _ => 0,
        }
    }
}

#[derive(Parser, Clone)]
pub struct Run {
    /// Specify the configuration file to be loaded by sniff
    pub config: String,
}
