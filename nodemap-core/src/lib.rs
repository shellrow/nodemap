pub mod option;
pub mod result;
pub mod process;
pub mod sys;
pub mod scan;

// All of the following is test code for cxx
#[cfg(feature = "cpp")]
use std::fs::read_to_string;

#[cfg(feature = "cpp")]
#[cxx::bridge]
mod ffi {
    pub struct PortOption {
        pub src_ip: String,
        pub src_port: u16,
        pub dst_ip_addr: String,
        pub dst_host_name: String,
        pub dst_ports: Vec<u16>,
        pub scan_type: String,
        pub timeout: u64,
        pub wait_time: u64,
        pub send_rate: u64,
        pub service_detection: bool,
        pub default_scan: bool,
        pub accept_invalid_certs: bool,
        pub save_file_path: String,
        pub async_scan: bool,
        pub os_detection: bool,
    }

    extern "Rust" {
        type TestResult;

        fn get_test_ports() -> Vec<u16>;

    }
}

#[cfg(feature = "cpp")]
pub struct TestResult {
    pub ip_addr: String,
    pub ports: Vec<u16>,
}

#[cfg(feature = "cpp")]
pub fn get_test_ports() -> Vec<u16> {
    vec![20,21,22,23,25,53,80,110,119,123,143,161,194,443]
}

#[cfg(feature = "cpp")]
#[allow(dead_code)]
impl ffi::PortOption {
    pub fn new() -> ffi::PortOption {
        ffi::PortOption {
            src_ip: String::new(),
            src_port: 53443,
            dst_ip_addr: String::new(),
            dst_host_name: String::new(),
            dst_ports: vec![],
            scan_type: String::from("SYN"),
            timeout: 30000,
            wait_time: 200,
            send_rate: 0,
            service_detection: false,
            default_scan: false,
            accept_invalid_certs: false,
            save_file_path: String::new(),
            async_scan: false,
            os_detection: false,
        }
    }
    pub fn set_src_port(&mut self, v: u16) {
        self.src_port = v;
    }
    pub fn set_dst_ip_addr(&mut self, v: String) {
        self.dst_ip_addr = v;
    }
    pub fn set_dst_host_name(&mut self, v: String) {
        self.dst_host_name = v;
    }
    pub fn set_dst_ports(&mut self, v: Vec<u16>) {
        self.dst_ports = v;
    }
    pub fn set_dst_ports_from_range(&mut self, from_v: u16, to_v: u16) {
        for port in from_v..to_v {
            self.dst_ports.push(port);
        }
    }
    pub fn set_dst_ports_from_csv(&mut self, v: String) {
        let values: Vec<&str> = v.split(",").collect();
        for p in values {
            match p.parse::<u16>(){
                Ok(port) =>{
                    self.dst_ports.push(port);
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
                    self.dst_ports.push(p);
                },
                Err(_) =>{},
            }
        }
    }
    pub fn set_timeout(&mut self, v: u64) {
        self.timeout = v;
    }
    pub fn set_wait_time(&mut self, v: u64) {
        self.wait_time = v;
    }
    pub fn set_send_rate(&mut self, v: u64) {
        self.send_rate = v;
    }
    pub fn set_service_detection(&mut self, v: bool) {
        self.service_detection = v;
    }
    pub fn set_default_scan(&mut self, v: bool) {
        self.default_scan = v;
    }
    pub fn set_src_ip(&mut self, v: String) {
        self.src_ip = v;
    }
    pub fn set_accept_invalid_certs(&mut self, v: bool) {
        self.accept_invalid_certs = v;
    }
    pub fn set_save_file_path(&mut self, v: String) {
        self.save_file_path = v;
    }
    pub fn set_async_scan(&mut self, async_scan: bool){
        self.async_scan = async_scan;
    }
    pub fn set_os_detection(&mut self, os_detection: bool){
        self.os_detection = os_detection;
    }
}
