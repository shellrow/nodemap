use std::sync::mpsc;
use super::option::ScanOption;

pub fn handle_port_scan(opt: ScanOption, msg_rx: mpsc::Receiver<String>) {
    
}

pub async fn handle_async_port_scan(opt: ScanOption, msg_rx: mpsc::Receiver<String>) {

}

pub fn handle_host_scan(opt: ScanOption, msg_rx: mpsc::Receiver<String>) {

}

pub async fn handle_async_host_scan(opt: ScanOption, msg_rx: mpsc::Receiver<String>) {

}

pub fn handle_ping(opt: ScanOption, msg_rx: mpsc::Receiver<String>) {

}

pub fn handle_traceroute(opt: ScanOption, msg_rx: mpsc::Receiver<String>) {

}

pub fn handle_uri_scan(opt: ScanOption, msg_rx: mpsc::Receiver<String>) {

}

pub fn handle_domain_scan(opt: ScanOption, msg_rx: mpsc::Receiver<String>) {

}
