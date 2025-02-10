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
    pub iface: Vec<String>,

    /// Detect traffic matching the given cidr. If not set, all traffic will be matched.
    #[arg(short = 'c', value_name = "cidr,", global = true)]
    pub cidr: Vec<String>,

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

#[derive(Subcommand)]
pub enum SubCmd {
    /// Detect all types of (TCP/UDP) traffic
    All = 0,

    /// Detect TCP type traffic
    Tcp = 1,

    /// Detect UDP type traffic
    Udp = 2,

    /// Check whether the sniff ebpf program can be mounted correctly
    Check,
}
