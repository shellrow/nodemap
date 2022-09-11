use std::net::IpAddr;
use std::sync::mpsc;
use std::thread;
use std::fs::{read, read_to_string};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use std::iter::Iterator;
use netscan::result::{HostScanResult};
use netscan::setting::Destination;
use netscan::blocking::{PortScanner, HostScanner};
use netscan::async_io::{PortScanner as AsyncPortScanner, HostScanner as AsyncHostScanner};
use netscan::os::{Fingerprinter, ProbeTarget, ProbeType, ProbeResult};
use netscan::service::{ServiceDetector, PortDatabase};
use webscan::RequestMethod;
use webscan::{UriScanner, DomainScanner};
use webscan::{UriScanResult, DomainScanResult};
use tracert::trace::{Tracer, TraceResult};
use tracert::ping::{Pinger};
use crate::option::{TargetInfo, Protocol};
use crate::result::{PortScanResult, PingStat, PingResult, ProbeStatus};
use crate::model::TCPFingerprint;
use super::option::ScanOption;

pub fn run_port_scan(opt: ScanOption, msg_tx: &mpsc::Sender<String>) -> netscan::result::PortScanResult {
    let mut port_scanner = match PortScanner::new(opt.src_ip){
        Ok(scanner) => (scanner),
        Err(e) => panic!("Error creating scanner: {}", e),
    };
    let dst: Destination = Destination::new(opt.targets[0].ip_addr, opt.targets[0].ports.clone());
    port_scanner.add_destination(dst);
    port_scanner.set_scan_type(opt.port_scan_type);
    port_scanner.set_timeout(opt.timeout);
    port_scanner.set_wait_time(opt.wait_time);
    port_scanner.set_send_rate(opt.send_rate);
    let rx = port_scanner.get_progress_receiver();
    let handle = thread::spawn(move|| {
        port_scanner.scan()
    });
    while let Ok(socket_addr) = rx.lock().unwrap().recv() {
        match msg_tx.send(socket_addr.to_string()) {
            Ok(_) => {},
            Err(_) => {},
        }
    }
    let result = handle.join().unwrap();
    result
}

pub async fn run_async_port_scan(opt: ScanOption, msg_tx: &mpsc::Sender<String>) -> netscan::result::PortScanResult {
    let mut port_scanner = match AsyncPortScanner::new(opt.src_ip){
        Ok(scanner) => (scanner),
        Err(e) => panic!("Error creating scanner: {}", e),
    };
    let dst: Destination = Destination::new(opt.targets[0].ip_addr, opt.targets[0].ports.clone());
    port_scanner.add_destination(dst);
    port_scanner.set_scan_type(opt.port_scan_type);
    port_scanner.set_timeout(opt.timeout);
    port_scanner.set_wait_time(opt.wait_time);
    port_scanner.set_send_rate(opt.send_rate);
    let rx = port_scanner.get_progress_receiver();
    let handle = thread::spawn(move|| {
        async_io::block_on(async {
            port_scanner.scan().await
        })
    });
    while let Ok(socket_addr) = rx.lock().unwrap().recv() {
        match msg_tx.send(socket_addr.to_string()) {
            Ok(_) => {},
            Err(_) => {},
        }
    }
    let result = handle.join().unwrap();
    result
}

pub fn run_host_scan(opt: ScanOption, msg_tx: &mpsc::Sender<String>) -> HostScanResult {
    let mut host_scanner = match HostScanner::new(opt.src_ip){
        Ok(scanner) => (scanner),
        Err(e) => panic!("Error creating scanner: {}", e),
    };
    for target in opt.targets {
        let dst: Destination = Destination::new(target.ip_addr, target.ports);
        host_scanner.add_destination(dst);
    }
    host_scanner.set_scan_type(opt.host_scan_type);
    host_scanner.set_timeout(opt.timeout);
    host_scanner.set_wait_time(opt.wait_time);
    host_scanner.set_send_rate(opt.send_rate);
    let rx = host_scanner.get_progress_receiver();
    let handle = thread::spawn(move|| {
        host_scanner.scan()
    });
    while let Ok(socket_addr) = rx.lock().unwrap().recv() {
        match msg_tx.send(socket_addr.to_string()) {
            Ok(_) => {},
            Err(_) => {},
        }
    }
    let result = handle.join().unwrap();
    result
}

pub async fn run_async_host_scan(opt: ScanOption, msg_tx: &mpsc::Sender<String>) -> HostScanResult {
    let mut host_scanner = match AsyncHostScanner::new(opt.src_ip){
        Ok(scanner) => (scanner),
        Err(e) => panic!("Error creating scanner: {}", e),
    };
    for target in opt.targets {
        let dst: Destination = Destination::new(target.ip_addr, target.ports);
        host_scanner.add_destination(dst);
    }
    host_scanner.set_scan_type(opt.host_scan_type);
    host_scanner.set_timeout(opt.timeout);
    host_scanner.set_wait_time(opt.wait_time);
    host_scanner.set_send_rate(opt.send_rate);
    let rx = host_scanner.get_progress_receiver();
    let handle = thread::spawn(move|| {
        async_io::block_on(async {
            host_scanner.scan().await
        })
    });
    while let Ok(socket_addr) = rx.lock().unwrap().recv() {
        match msg_tx.send(socket_addr.to_string()) {
            Ok(_) => {},
            Err(_) => {},
        }
    }
    let result = handle.join().unwrap();
    result
}

pub fn run_service_detection(targets: Vec<TargetInfo>, msg_tx: &mpsc::Sender<String>, port_db: Option<PortDatabase>) -> HashMap<IpAddr, HashMap<u16, String>> {
    let mut map: HashMap<IpAddr, HashMap<u16, String>> = HashMap::new();
    for target in targets {
        let mut service_detector = ServiceDetector::new();
        service_detector.set_dst_ip(target.ip_addr);
        service_detector.set_open_ports(target.ports);
        let service_map: HashMap<u16, String> = service_detector.detect(port_db.clone());
        map.insert(target.ip_addr, service_map);
        match msg_tx.send(target.ip_addr.to_string()) {
            Ok(_) => {},
            Err(_) => {},
        }
    }
    map
}

pub fn run_os_fingerprinting(opt: ScanOption, targets: Vec<TargetInfo>, _msg_tx: &mpsc::Sender<String>) -> Vec<ProbeResult> {
    let mut fingerprinter = Fingerprinter::new(opt.src_ip).unwrap();
    fingerprinter.set_wait_time(opt.wait_time);
    for target in targets {
        let probe_target: ProbeTarget = ProbeTarget {
            ip_addr: target.ip_addr,
            open_tcp_ports: target.ports,
            closed_tcp_port: 0,
            open_udp_port: 0,
            closed_udp_port: 33455,
        };
        fingerprinter.add_probe_target(probe_target);
    }
    fingerprinter.add_probe_type(ProbeType::IcmpEchoProbe);
    fingerprinter.add_probe_type(ProbeType::IcmpUnreachableProbe);
    fingerprinter.add_probe_type(ProbeType::TcpProbe);
    let results = fingerprinter.probe();
    results
}

pub async fn run_service_scan(opt: ScanOption, msg_tx: &mpsc::Sender<String>) -> PortScanResult {
    let mut result: PortScanResult = PortScanResult::new();
    // Port Scan
    match msg_tx.send(String::from("START_PORTSCAN")) {
        Ok(_) => {},
        Err(_) => {},
    }
    let ps_result: netscan::result::PortScanResult = run_async_port_scan(opt.clone(), &msg_tx).await;
    match msg_tx.send(String::from("END_PORTSCAN")) {
        Ok(_) => {},
        Err(_) => {},
    }
    // Service Detection
    let mut sd_result: HashMap<IpAddr, HashMap<u16, String>> = HashMap::new();
    let mut sd_time: Duration = Duration::from_millis(0);
    if opt.service_detection && ps_result.result_map.keys().len() > 0 {
        match msg_tx.send(String::from("START_SERVICEDETECTION")) {
            Ok(_) => {},
            Err(_) => {},
        }
        let mut sd_targets: Vec<TargetInfo> = vec![];
        let ip = ps_result.result_map.keys().last().unwrap().clone();
        let mut target: TargetInfo  = TargetInfo::new_with_ip_addr(ip);
        target.ports = ps_result.get_open_ports(ip);
        sd_targets.push(target);
        let port_db: PortDatabase = PortDatabase { http_ports: opt.http_ports.clone(), https_ports: opt.https_ports.clone() };
        let start_time: Instant = Instant::now();
        sd_result = run_service_detection(sd_targets, &msg_tx, Some(port_db));
        sd_time = Instant::now().duration_since(start_time);
        match msg_tx.send(String::from("END_SERVICEDETECTION")) {
            Ok(_) => {},
            Err(_) => {},
        }
    }
    // os fingerprinting
    let mut od_result: Vec<ProbeResult> = vec![];
    let mut od_time: Duration = Duration::from_millis(0);
    if opt.os_detection && ps_result.result_map.keys().len() > 0 {
        match msg_tx.send(String::from("START_OSDETECTION")) {
            Ok(_) => {},
            Err(_) => {},
        }
        let ip = ps_result.result_map.keys().last().unwrap().clone();
        let mut od_targets: Vec<TargetInfo> = vec![];
        let mut target: TargetInfo  = TargetInfo::new_with_ip_addr(ip);
        target.ports = ps_result.get_open_ports(ip);
        od_targets.push(target);
        let start_time: Instant = Instant::now();
        od_result = run_os_fingerprinting(opt.clone(),  od_targets, &msg_tx);
        od_time = Instant::now().duration_since(start_time);
        match msg_tx.send(String::from("END_OSDETECTION")) {
            Ok(_) => {},
            Err(_) => {},
        }
    }
    // return crate::result::PortScanResult
    if ps_result.result_map.keys().len() > 0 {
        let ip = ps_result.result_map.keys().last().unwrap().clone();
        let ports = ps_result.result_map.values().last().unwrap().clone();
        let tcp_map = opt.tcp_map;
        let t_map: HashMap<u16, String> = HashMap::new();
        let service_map = sd_result.get(&ip).unwrap_or(&t_map);
        // PortInfo
        for port in ports {
            let port_info = crate::result::PortInfo { 
                port_number: port.port.clone(), 
                port_status: format!("{:?}", port.status), 
                service_name: tcp_map.get(&port.port.to_string()).unwrap_or(&String::new()).to_string(), 
                service_version: service_map.get(&port.port).unwrap_or(&String::new()).to_string(), 
                remark: String::new(), 
            };     
            result.ports.push(port_info);  
        }
        // HostInfo
        let tcp_fingetprint =  if od_result.len() > 0 { crate::os::verify_fingerprints(od_result[0].tcp_fingerprint.clone(), opt.tcp_fingerprints) } else{ TCPFingerprint::new() };
        let host_info = crate::result::HostInfo {
            ip_addr: ip.to_string(),
            host_name: dns_lookup::lookup_addr(&ip).unwrap_or(String::new()),
            mac_addr: String::new(),
            vendor_info: String::new(),
            os_name: tcp_fingetprint.os_name ,
            cpe: tcp_fingetprint.cpe,
        };
        result.host = host_info;
        result.port_scan_time = ps_result.scan_time;
        result.service_detection_time = sd_time;
        result.os_detection_time = od_time;
        result.total_scan_time = result.port_scan_time + result.service_detection_time + result.os_detection_time;
    }
    return result;
}

pub async fn run_node_scan(_opt: ScanOption, _msg_tx: &mpsc::Sender<String>) {
    // host scan
    // get mac addresses (lan only)
    // guess OS from TTL
    // return crate::result::HostScanResult
}

pub fn run_ping(opt: ScanOption, msg_tx: &mpsc::Sender<String>) -> PingStat {
    let mut pinger: Pinger = Pinger::new(opt.targets[0].ip_addr).unwrap();
    match opt.protocol {
        Protocol::ICMPv4 => {
            pinger.set_protocol(tracert::protocol::Protocol::Icmpv4);
        },
        Protocol::ICMPv6 => {
            pinger.set_protocol(tracert::protocol::Protocol::Icmpv6);
        },
        Protocol::TCP => {
            pinger.set_protocol(tracert::protocol::Protocol::Tcp);
            pinger.dst_port = opt.targets[0].ports[0];
        },
        Protocol::UDP => {
            pinger.set_protocol(tracert::protocol::Protocol::Udp);
            pinger.dst_port = opt.targets[0].ports[0];
        },
    }
    let rx = pinger.get_progress_receiver();
    let handle = thread::spawn(move|| {
        pinger.ping()
    });
    while let Ok(node) = rx.lock().unwrap().recv() {
        match msg_tx.send(format!("[{}] SEQ:{} IP:{} TTL:{:?} HOP:{:?} RTT:{:?}", opt.protocol.name(), node.seq, node.ip_addr, node.ttl.unwrap_or(0), node.hop.unwrap_or(0), node.rtt)) {
            Ok(_) => {},
            Err(_) => {},
        }
    }
    let ping_result: tracert::ping::PingResult = handle.join().unwrap().unwrap();
    let mut result = PingStat::new();
    result.probe_time = ping_result.probe_time;
    result.transmitted_count = ping_result.results.len();
    result.received_count = ping_result.results.len();
    let mut rtt_vec: Vec<u128> = vec![];
    for node in ping_result.results {
        let r = PingResult {
            seq: node.seq,
            ip_addr : node.ip_addr,
            host_name : node.host_name,
            port_number : if opt.targets[0].ports.len() > 0 { Some(opt.targets[0].ports[0]) } else { None }, 
            ttl : node.ttl.unwrap_or(0),
            hop : node.hop.unwrap_or(0),
            rtt : node.rtt,
            status : ProbeStatus::Done,
            protocol : opt.protocol.name(),
        };
        result.ping_results.push(r);
        rtt_vec.push(node.rtt.as_millis());
    }
    let min: u128;
    let max: u128;
    let avg: u128 = (rtt_vec.iter().sum::<u128>() as usize / rtt_vec.len()) as u128;
    match rtt_vec.iter().min() {
        Some(n) => min = *n,
        None => unreachable!(),
    }
    match rtt_vec.iter().max() {
        Some(n) => max = *n,
        None => unreachable!(),
    }
    result.min = Duration::from_millis(min as u64);
    result.max = Duration::from_millis(max as u64);
    result.avg = Duration::from_millis(avg as u64);

    result
}

pub fn run_traceroute(opt: ScanOption, msg_tx: &mpsc::Sender<String>) -> TraceResult {
    let tracer: Tracer = Tracer::new(opt.targets[0].ip_addr).unwrap();
    let rx = tracer.get_progress_receiver();
    let handle = thread::spawn(move|| {
        tracer.trace()
    });
    while let Ok(node) = rx.lock().unwrap().recv() {
        match msg_tx.send(format!("{} {} {:?} {:?}", node.seq, node.ip_addr, node.hop, node.rtt)) {
            Ok(_) => {},
            Err(_) => {},
        }
    }
    let result = handle.join().unwrap().unwrap();
    result
}

pub async fn run_uri_scan(opt: ScanOption, msg_tx: &mpsc::Sender<String>) -> UriScanResult {
    let mut uri_scanner = match UriScanner::new(){
        Ok(scanner) => (scanner),
        Err(e) => panic!("Error creating scanner: {}", e),
    };
    uri_scanner.set_base_uri(opt.targets[0].base_uri.clone());
    if opt.use_wordlist {
        let data = read_to_string(opt.wordlist_path);
        let text = match data {
            Ok(content) => content,
            Err(e) => {panic!("Could not open or find file: {}", e);}
        };
        let word_list: Vec<&str> = text.trim().split("\n").collect();
        for word in word_list {
            uri_scanner.add_word(word.to_string());
        }
    }
    if opt.use_content {
        match read(opt.content_path.to_string()) {
            Ok(ct) => {
                let sep = b'\n';
                ct.split(|b| b == &sep )
                    .for_each(|c| uri_scanner.add_content(c.to_vec()));
            },
            Err(e) => {panic!("Could not open or find content file {} due to {}", opt.content_path.to_string(), e);}
        }
    }
    if !opt.request_method.is_empty() {
        if opt.request_method.to_uppercase() == "POST" {
            uri_scanner.set_request_method(RequestMethod::Post);
        }else{
            uri_scanner.set_request_method(RequestMethod::Get);
        }
    }
    uri_scanner.set_timeout(opt.timeout);
    let rx = uri_scanner.get_progress_receiver();
    let handle = thread::spawn(move|| {
        async_io::block_on(async {
            uri_scanner.scan().await
        })
    });
    while let Ok(uri) = rx.lock().unwrap().recv() {
        match msg_tx.send(uri) {
            Ok(_) => {},
            Err(_) => {},
        }
    }
    let result = handle.join().unwrap();
    result
}

pub fn run_domain_scan(opt: ScanOption, msg_tx: &mpsc::Sender<String>) -> DomainScanResult {
    let mut domain_scanner = match DomainScanner::new(){
        Ok(scanner) => (scanner),
        Err(e) => panic!("Error creating scanner: {}", e),
    };
    domain_scanner.set_base_domain(opt.targets[0].base_domain.clone());
    if opt.use_wordlist {
        let data = read_to_string(opt.wordlist_path.to_string());
        let text = match data {
            Ok(content) => content,
            Err(e) => {panic!("Could not open or find file: {}", e);}
        };
        let word_list: Vec<&str> = text.trim().split("\n").collect();
        for d in word_list{
            domain_scanner.add_word(d.to_string());
        }
    }
    domain_scanner.set_timeout(opt.timeout);
    let rx = domain_scanner.get_progress_receiver();
    let handle = thread::spawn(move|| {
        async_io::block_on(async {
            domain_scanner.scan().await
        })
    });
    while let Ok(domain) = rx.lock().unwrap().recv() {
        match msg_tx.send(domain) {
            Ok(_) => {},
            Err(_) => {},
        }
    }
    let result = handle.join().unwrap();
    result
}
