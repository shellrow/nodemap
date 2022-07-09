use netscan::setting::ScanType;
use std::time::Duration;
use std::fs::read_to_string;
use std::net::{IpAddr, Ipv4Addr};
use ipnet::{Ipv4Net};

pub enum ExecType {
    PortScan,
    HostScan,
    Ping,
    Traceroute,
    UriScan,
    DomainScan,
    BatchScan,
    PassiveScan
}

pub struct TargetInfo {
    pub ip_addr: IpAddr,
    pub host_name: String,
    pub ports: Vec<u16>,
}

pub struct ScanOption {
    pub exec_type: ExecType,
    pub interface_index: u16,
    pub interface_name: String,
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub targets: Vec<TargetInfo>,
    pub protocol: String,
    pub max_hop: u8,
    pub timeout: Duration,
    pub wait_time: Duration,
    pub send_rate: Duration,
    pub default_scan: bool,
    pub service_detection: bool,
    pub os_detection: bool,
    pub async_scan: bool,
    pub use_wordlist: bool,
    pub use_content: bool,
    pub accept_invalid_certs: bool,
    pub wordlist_path: String,
    pub content_path: String,
    pub request_method: String,
    pub data_provider: String,
    pub save_file_path: String,
}
