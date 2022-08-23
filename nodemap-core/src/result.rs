use std::time::Duration;
use std::net::IpAddr;
use serde::{Serialize, Deserialize};

/// Exit status of probe
#[derive(Clone, Debug ,Serialize, Deserialize)]
pub enum ProbeStatus {
    /// Successfully completed
    Done,
    /// Interrupted by error
    Error,
    /// Execution time exceeds the configured timeout value
    Timeout,
}

#[derive(Clone, Debug ,Serialize, Deserialize)]
pub struct PortInfo {
    pub port_number: u16,
    pub port_status: String,
    pub service_name: String,
    pub service_version: String,
    pub remark: String,
}

impl PortInfo {
    pub fn new() -> PortInfo {
        PortInfo { 
            port_number: 0, 
            port_status: String::new(), 
            service_name: String::new(), 
            service_version: String::new(), 
            remark: String::new(), 
        }
    }
}

#[derive(Clone, Debug ,Serialize, Deserialize)]
pub struct HostInfo {
    pub ip_addr: String,
    pub host_name: String,
    pub mac_addr: String,
    pub vendor_info: String,
    pub os_name: String,
    pub cpe: String,
}

impl HostInfo {
    pub fn new() -> HostInfo {
        HostInfo { 
            ip_addr: String::new(), 
            host_name: String::new(), 
            mac_addr: String::new(), 
            vendor_info: String::new(), 
            os_name: String::new(), 
            cpe: String::new() 
        }
    }
}

#[derive(Clone, Debug ,Serialize, Deserialize)]
pub struct PortScanResult {
    pub ports: Vec<PortInfo>,
    pub host: HostInfo,
    pub port_scan_time: Duration,
    pub service_detection_time: Duration,
    pub os_detection_time: Duration,
    pub total_scan_time: Duration,
}

impl PortScanResult {
    pub fn new() -> PortScanResult {
        PortScanResult { 
            ports: vec![], 
            host: HostInfo::new(), 
            port_scan_time: Duration::from_millis(0), 
            service_detection_time: Duration::from_millis(0), 
            os_detection_time: Duration::from_millis(0), 
            total_scan_time: Duration::from_millis(0) 
        }
    }
}

#[derive(Clone, Debug ,Serialize, Deserialize)]
pub struct HostScanResult {
    pub hosts: Vec<HostInfo>,
    pub host_scan_time: Duration,
    pub os_detection_time: Duration,
    pub total_scan_time: Duration,
}

impl HostScanResult {
    pub fn new() -> HostScanResult {
        HostScanResult { 
            hosts: vec![], 
            host_scan_time: Duration::from_millis(0), 
            os_detection_time: Duration::from_millis(0), 
            total_scan_time: Duration::from_millis(0) 
        }
    }
}

#[derive(Clone, Debug ,Serialize, Deserialize)]
pub struct PingResult {
    /// Sequence number
    pub seq: u8,
    /// IP address
    pub ip_addr: IpAddr,
    /// Host name
    pub host_name: String,
    /// Port
    pub port_number: Option<u16>, 
    /// Time To Live
    pub ttl: u8,
    /// Number of hops
    pub hop: u8,
    /// Round Trip Time
    pub rtt: Duration,
    /// Status
    pub status: ProbeStatus,
    /// Protocol
    pub protocol: String,
}

#[derive(Clone, Debug ,Serialize, Deserialize)]
pub struct PingStat {
    /// Results
    pub ping_results: Vec<PingResult>,
    /// The entire ping probe time
    pub probe_time: Duration,
    /// Transmitted packets
    pub transmitted_count: u8,
    /// Received packets
    pub received_count: u8,
    /// Minimum RTT
    pub min: Duration,
    /// Avarage RTT
    pub avg: Duration,
    /// Maximum RTT
    pub max: Duration,
}
