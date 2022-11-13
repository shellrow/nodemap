use std::net::IpAddr;
use std::sync::mpsc::{channel ,Sender, Receiver};
use std::thread;
use serde::{Serialize, Deserialize};
use nodemap_core::option::{TargetInfo, ScanOption, CommandType, ScanType};
use nodemap_core::result::{PortScanResult};
use nodemap_core::process;
use nodemap_core::scan;
use nodemap_core::validator;
use nodemap_core::network;

use crate::db;
use crate::define;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PortArg {
    target_host: String,
    port_option: String,
    ports: Vec<u16>,
    scan_type: String,
    async_flag: bool,
    service_detection_flag: bool,
    os_detection_flag: bool,
    save_flag: bool,
}

impl PortArg {
    pub fn new() -> PortArg {
        PortArg {
            target_host: String::new(),
            port_option: String::new(),
            ports: vec![],
            scan_type: String::new(),
            async_flag: false,
            service_detection_flag: false,
            os_detection_flag: false,
            save_flag: false,
        }
    }
    pub fn to_scan_option(&self) -> nodemap_core::option::ScanOption {
        let mut opt: ScanOption = ScanOption::default();
        opt.command_type = CommandType::PortScan;
        opt.tcp_map = db::get_tcp_map();
        let ip_addr: IpAddr;
        if validator::is_ipaddr(self.target_host.clone()) {
            ip_addr = self.target_host.parse::<IpAddr>().unwrap();
        }else{
            match network::lookup_host_name(self.target_host.clone()) {
                Some(ip) => {
                    ip_addr = ip;
                },
                None => {
                    return opt;
                }
            }
        }
        let mut target: TargetInfo = TargetInfo::new_with_ip_addr(ip_addr);
        if self.port_option == String::from("well_known") {
            target.ports = db::get_default_ports();
        }else if self.port_option == String::from("custom_list") {
            target.ports = self.ports.clone();
        }else{
            target.ports = db::get_default_ports();
            opt.default_scan = true;
        }
        if self.async_flag {
            opt.async_scan = true;
        }
        if self.service_detection_flag {
            opt.service_detection = true;
            opt.http_ports = db::get_http_ports();
            opt.https_ports = db::get_https_ports();
        }
        if self.os_detection_flag {
            opt.os_detection = true;
            opt.tcp_fingerprints = db::get_tcp_fingerprints(); 
        }
        opt.targets.push(target);
        opt
    }
}

// Test commands
#[tauri::command]
pub fn test_command() {
    println!("I was invoked from JS!");
}

#[tauri::command]
pub fn test_command_arg(invoke_message: String) {
    println!("I was invoked from JS, with this message: {}", invoke_message);
}

#[tauri::command]
pub fn test_command_return() -> String {
    String::from("Hello from Rust!")
}

#[tauri::command]
pub fn test_command_result() -> Result<String, String> {
    // Fail
    //Err("This failed!".into())
    // Success
    Ok("This worked!".into())
}

async fn some_async_function() -> Option<String> {
    Some("response".into())
}

#[tauri::command]
pub async fn test_command_async() {
    let result = some_async_function().await;
    println!("Result: {}", result.unwrap());
}

// Commands
#[tauri::command]
pub async fn exec_portscan(opt: PortArg) -> PortScanResult {
    let probe_opt: ScanOption = opt.to_scan_option();
    let m_probe_opt: ScanOption = probe_opt.clone();
    let (msg_tx, msg_rx): (Sender<String>, Receiver<String>) = channel();
    let handle = thread::spawn(move|| {
        async_io::block_on(async {
            scan::run_service_scan(m_probe_opt, &msg_tx).await
        })
    });
    let result: PortScanResult = handle.join().unwrap();
    result
}
