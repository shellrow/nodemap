use std::sync::mpsc::{channel ,Sender, Receiver};
use std::thread;
use tauri::Manager;
use nodemap_core::option::{ScanOption};
use nodemap_core::result::{PortScanResult, HostScanResult, PingStat, TraceResult};
use nodemap_core::scan;
use nodemap_core::network;

use crate::models;

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
pub async fn exec_portscan(opt: models::PortArg) -> PortScanResult {
    let probe_opt: ScanOption = opt.to_scan_option();
    let m_probe_opt: ScanOption = probe_opt.clone();
    let (msg_tx, _msg_rx): (Sender<String>, Receiver<String>) = channel();
    let handle = thread::spawn(move|| {
        async_io::block_on(async {
            scan::run_service_scan(m_probe_opt, &msg_tx).await
        })
    });
    let result: PortScanResult = handle.join().unwrap();
    result
}

#[tauri::command]
pub async fn exec_hostscan(opt: models::HostArg) -> HostScanResult {
    let probe_opt: ScanOption = opt.to_scan_option();
    let m_probe_opt: ScanOption = probe_opt.clone();
    let (msg_tx, _msg_rx): (Sender<String>, Receiver<String>) = channel();
    let handle = thread::spawn(move|| {
        async_io::block_on(async {
            scan::run_node_scan(m_probe_opt, &msg_tx).await
        })
    });
    let result: HostScanResult = handle.join().unwrap();
    result
}

#[tauri::command]
pub async fn exec_ping(opt: models::PingArg, app_handle: tauri::AppHandle) -> PingStat {
    let probe_opt: ScanOption = opt.to_scan_option();
    let m_probe_opt: ScanOption = probe_opt.clone();
    let (msg_tx, msg_rx): (Sender<String>, Receiver<String>) = channel();
    let handle = thread::spawn(move|| {
        async_io::block_on(async {
            scan::run_ping(m_probe_opt, &msg_tx)
        })
    });
    //Progress
    while let Ok(msg) = msg_rx.recv() {
        app_handle.emit_all("ping_progress", format!("{}", msg)).unwrap();
    } 
    let result: PingStat = handle.join().unwrap();
    result
}

#[tauri::command]
pub async fn exec_traceroute(opt: models::TracerouteArg, app_handle: tauri::AppHandle) -> TraceResult {
    let probe_opt: ScanOption = opt.to_scan_option();
    let m_probe_opt: ScanOption = probe_opt.clone();
    let (msg_tx, msg_rx): (Sender<String>, Receiver<String>) = channel();
    let handle = thread::spawn(move|| {
        async_io::block_on(async {
            scan::run_traceroute(m_probe_opt, &msg_tx)
        })
    });
    //Progress
    while let Ok(msg) = msg_rx.recv() {
        app_handle.emit_all("trace_progress", format!("{}", msg)).unwrap();
    } 
    let result: TraceResult = handle.join().unwrap();
    result
}

#[tauri::command]
pub fn lookup_hostname(hostname: String) -> String {
    if let Some(ip_addr) = network::lookup_host_name(hostname) {
        return ip_addr.to_string();
    }else{
        return String::new();
    }
}

#[tauri::command]
pub fn lookup_ipaddr(ipaddr: String) -> String {
    return network::lookup_ip_addr(ipaddr);
}
