use std::time::Duration;
use serde::{Serialize, Deserialize};

#[derive(Clone, Debug ,Serialize, Deserialize)]
pub struct PortInfo {
    pub port_number: u16,
    pub port_status: String,
    pub service_name: String,
    pub service_version: String,
    pub remark: String,
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

#[derive(Clone, Debug ,Serialize, Deserialize)]
pub struct PortScanResult {
    pub ports: Vec<PortInfo>,
    pub host: HostInfo,
    pub port_scan_time: Duration,
    pub service_detection_time: Duration,
    pub os_detection_time: Duration,
    pub total_scan_time: Duration,
}

#[derive(Clone, Debug ,Serialize, Deserialize)]
pub struct HostScanResult {
    pub hosts: Vec<HostInfo>,
    pub host_scan_time: Duration,
    pub os_detection_time: Duration,
    pub total_scan_time: Duration,
}
