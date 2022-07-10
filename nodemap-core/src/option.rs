use std::time::Duration;
use std::net::{IpAddr, Ipv4Addr};
use std::fs::read_to_string;
use ipnet::Ipv4Net;

use super::network;

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
    pub fn new_with_ip_addr(ip_addr: IpAddr) -> TargetInfo {
        TargetInfo {
            ip_addr: ip_addr,
            host_name: String::new(),
            ports: vec![],
            base_uri: String::new(),
            base_domain: String::new(),
        }
    }
    pub fn new_with_base_uri(base_uri: String) -> TargetInfo {
        TargetInfo {
            ip_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            host_name: String::new(),
            ports: vec![],
            base_uri: base_uri,
            base_domain: String::new(),
        }
    }
    pub fn new_with_base_domain(base_domain: String) -> TargetInfo {
        TargetInfo {
            ip_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            host_name: String::new(),
            ports: vec![],
            base_uri: String::new(),
            base_domain: base_domain,
        }
    }
    pub fn set_dst_ports_from_range(&mut self, from_v: u16, to_v: u16) {
        for port in from_v..to_v {
            self.ports.push(port);
        }
    }
    pub fn set_dst_ports_from_csv(&mut self, v: String) {
        let values: Vec<&str> = v.split(",").collect();
        for p in values {
            match p.parse::<u16>(){
                Ok(port) =>{
                    self.ports.push(port);
                },
                Err(_) =>{},
            }
        }
    }
    pub fn set_dst_ports_from_list(&mut self, v: String) {
        let data = read_to_string(v);
        let text = match data {
            Ok(content) => content,
            Err(_) => String::new(),
        };
        let port_list: Vec<&str> = text.trim().split("\n").collect();
        for port in port_list {
            match port.parse::<u16>(){
                Ok(p) =>{
                    self.ports.push(p);
                },
                Err(_) =>{},
            }
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
    pub fn set_dst_hosts_from_na(&mut self, v: String, prefix_len: u8) {
        match v.parse::<IpAddr>(){
            Ok(addr) => {
                match addr {
                    IpAddr::V4(ipv4_addr) => {
                        let net: Ipv4Net = Ipv4Net::new(ipv4_addr, prefix_len).unwrap();
                        let nw_addr = Ipv4Net::new(net.network(), prefix_len).unwrap();
                        let hosts: Vec<Ipv4Addr> = nw_addr.hosts().collect();
                        for host in hosts {
                            self.targets.push(TargetInfo::new_with_ip_addr(IpAddr::V4(host)));
                        }
                    },
                    IpAddr::V6(_) => {},
                }
            },
            Err(_) =>{},
        }
        //TODO: add v6 support
    }
    pub fn set_dst_hosts_from_list(&mut self, v: String) {
        let data = read_to_string(v);
        let text = match data {
            Ok(content) => content,
            Err(_) => String::new(),
        };
        let host_list: Vec<&str> = text.trim().split("\n").collect();
        for host in host_list {
            match host.parse::<IpAddr>(){
                Ok(addr) =>{
                    self.targets.push(TargetInfo::new_with_ip_addr(addr));
                },
                Err(_) =>{
                    if let Some(addr) = network::lookup_host_name(host.to_string()) {
                        self.targets.push(TargetInfo::new_with_ip_addr(addr));
                    }
                },
            }
        }
    }
}
