use std::time::Duration;
use std::net::{IpAddr, Ipv4Addr};

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum CommandType {
    PortScan,
    HostScan,
    Ping,
    Traceroute,
    UriScan,
    DomainScan,
    BatchScan,
    PassiveScan
}

impl CommandType {
    pub fn name(&self) -> String {
        match *self {
            CommandType::PortScan => String::from("Port scan"),
            CommandType::HostScan => String::from("Host scan"),
            CommandType::Ping => String::from("Ping"),
            CommandType::Traceroute => String::from("Traceroute"),
            CommandType::UriScan => String::from("URI scan"),
            CommandType::DomainScan => String::from("Domain scan"),
            CommandType::BatchScan => String::from("Batch scan"),
            CommandType::PassiveScan => String::from("Passive scan"),
        }
    }
    pub fn description(&self) -> String {
        match *self {
            CommandType::PortScan => String::from("Port scan"),
            CommandType::HostScan => String::from("Host scan"),
            CommandType::Ping => String::from("Ping"),
            CommandType::Traceroute => String::from("Traceroute"),
            CommandType::UriScan => String::from("URI scan"),
            CommandType::DomainScan => String::from("Domain scan"),
            CommandType::BatchScan => String::from("Batch scan"),
            CommandType::PassiveScan => String::from("Passive scan"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Protocol {
    TCP,
    UDP,
    ICMPv4,
    ICMPv6,
}

impl Protocol {
    pub fn name(&self) -> String {
        match *self {
            Protocol::TCP => String::from("TCP"),
            Protocol::UDP => String::from("UDP"),
            Protocol::ICMPv4 => String::from("ICMPv4"),
            Protocol::ICMPv6 => String::from("ICMPv6"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct TargetInfo {
    pub ip_addr: IpAddr,
    pub host_name: String,
    pub ports: Vec<u16>,
    pub base_uri: String,
    pub base_domain: String,
}

impl TargetInfo {
    pub fn new() -> TargetInfo {
        TargetInfo {
            ip_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            host_name: String::new(),
            ports: vec![],
            base_uri: String::new(),
            base_domain: String::new(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ScanOption {
    pub command_type: CommandType,
    pub interface_index: u32,
    pub interface_name: String,
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub targets: Vec<TargetInfo>,
    pub protocol: Protocol,
    pub max_hop: u8,
    pub host_scan_type: netscan::setting::ScanType,
    pub port_scan_type: netscan::setting::ScanType,
    pub ping_type: tracert::protocol::Protocol,
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

impl ScanOption {
    pub fn new() -> ScanOption {
        ScanOption{
            command_type: CommandType::PortScan,
            interface_index: u32::MIN,
            interface_name: String::new(),
            src_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            src_port: u16::MIN,
            targets: vec![],
            protocol: Protocol::TCP,
            max_hop: 64,
            host_scan_type: netscan::setting::ScanType::IcmpPingScan,
            port_scan_type: netscan::setting::ScanType::TcpConnectScan,
            ping_type: tracert::protocol::Protocol::Icmpv4,
            timeout: Duration::from_millis(30000),
            wait_time: Duration::from_millis(200),
            send_rate: Duration::from_millis(0),
            default_scan: true,
            service_detection: false,
            os_detection: false,
            async_scan: true,
            use_wordlist: false,
            use_content: false,
            accept_invalid_certs: false,
            wordlist_path: String::new(),
            content_path: String::new(),
            request_method: String::new(),
            data_provider: String::new(),
            save_file_path: String::new(),
        }
    }
}