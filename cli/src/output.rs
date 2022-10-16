use term_table::{Table, TableStyle};
use term_table::table_cell::{TableCell,Alignment};
use term_table::row::Row;
use nodemap_core::option::{CommandType, ScanOption};
use nodemap_core::result::{PortScanResult, HostScanResult, PingStat, TraceResult, DomainScanResult};

pub fn show_options(opt: ScanOption) {
    let mut table = Table::new();
    table.max_column_width = 60;
    table.separate_rows = false;
    table.style = TableStyle::blank();
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Options:", 1, Alignment::Left)
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("\tProbe Type", 1, Alignment::Left),
        TableCell::new_with_alignment(opt.command_type.name(), 1, Alignment::Left)
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("\tProtocol", 1, Alignment::Left),
        TableCell::new_with_alignment(opt.protocol.name(), 1, Alignment::Left)
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("\tInterface Name", 1, Alignment::Left),
        TableCell::new_with_alignment(opt.interface_name, 1, Alignment::Left)
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("\tSource IP Address", 1, Alignment::Left),
        TableCell::new_with_alignment(opt.src_ip, 1, Alignment::Left)
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("\tTimeout(ms)", 1, Alignment::Left),
        TableCell::new_with_alignment(opt.timeout.as_millis(), 1, Alignment::Left)
    ]));
    match opt.command_type {
        CommandType::PortScan => {
            table.add_row(Row::new(vec![
                TableCell::new_with_alignment("\tScan Type", 1, Alignment::Left),
                TableCell::new_with_alignment(opt.port_scan_type.name(), 1, Alignment::Left)
            ]));
            table.add_row(Row::new(vec![
                TableCell::new_with_alignment("\tAsync", 1, Alignment::Left),
                if opt.async_scan {
                    TableCell::new_with_alignment("True", 1, Alignment::Left)
                }else{
                    TableCell::new_with_alignment("False", 1, Alignment::Left)
                }
            ]));
            table.add_row(Row::new(vec![
                TableCell::new_with_alignment("\tSend Rate(ms)", 1, Alignment::Left),
                TableCell::new_with_alignment(opt.send_rate.as_millis(), 1, Alignment::Left)
            ]));
            table.add_row(Row::new(vec![
                TableCell::new_with_alignment("Target:", 1, Alignment::Left)
            ]));
            for target in opt.targets {
                table.add_row(Row::new(vec![
                    TableCell::new_with_alignment("\tIP Address", 1, Alignment::Left),
                    TableCell::new_with_alignment(target.ip_addr, 1, Alignment::Left)
                ]));
                if target.ports.len() > 10 {
                    table.add_row(Row::new(vec![
                        TableCell::new_with_alignment("\tPort", 1, Alignment::Left),
                        TableCell::new_with_alignment(format!("{} port(s)",target.ports.len()), 1, Alignment::Left)
                    ]));
                }else{
                    table.add_row(Row::new(vec![
                        TableCell::new_with_alignment("\tPort", 1, Alignment::Left),
                        TableCell::new_with_alignment(format!("{:?} port(s)",target.ports), 1, Alignment::Left)
                    ]));
                }
            }
        },
        CommandType::HostScan => {
            table.add_row(Row::new(vec![
                TableCell::new_with_alignment("\tScan Type", 1, Alignment::Left),
                TableCell::new_with_alignment(opt.port_scan_type.name(), 1, Alignment::Left)
            ]));
            table.add_row(Row::new(vec![
                TableCell::new_with_alignment("\tAsync", 1, Alignment::Left),
                if opt.async_scan {
                    TableCell::new_with_alignment("True", 1, Alignment::Left)
                }else{
                    TableCell::new_with_alignment("False", 1, Alignment::Left)
                }
            ]));
            table.add_row(Row::new(vec![
                TableCell::new_with_alignment("\tSend Rate(ms)", 1, Alignment::Left),
                TableCell::new_with_alignment(opt.send_rate.as_millis(), 1, Alignment::Left)
            ]));
            table.add_row(Row::new(vec![
                TableCell::new_with_alignment("Target:", 1, Alignment::Left)
            ]));
            table.add_row(Row::new(vec![
                TableCell::new_with_alignment("\tHost", 1, Alignment::Left),
                TableCell::new_with_alignment(format!("{} host(s)", opt.targets.len()), 1, Alignment::Left)
            ]));
        },
        CommandType::Ping => {
            table.add_row(Row::new(vec![
                TableCell::new_with_alignment("\tPing Type", 1, Alignment::Left),
                TableCell::new_with_alignment(opt.ping_type.name(), 1, Alignment::Left)
            ]));
            table.add_row(Row::new(vec![
                TableCell::new_with_alignment("\tCount", 1, Alignment::Left),
                TableCell::new_with_alignment(opt.count, 1, Alignment::Left)
            ]));
            table.add_row(Row::new(vec![
                TableCell::new_with_alignment("\tSend Rate(ms)", 1, Alignment::Left),
                TableCell::new_with_alignment(opt.send_rate.as_millis(), 1, Alignment::Left)
            ]));
            table.add_row(Row::new(vec![
                TableCell::new_with_alignment("Target:", 1, Alignment::Left)
            ]));
            for target in opt.targets {
                table.add_row(Row::new(vec![
                    TableCell::new_with_alignment("\tHost", 1, Alignment::Left),
                    TableCell::new_with_alignment(target.ip_addr, 1, Alignment::Left)
                ]));
            }
        },
        CommandType::Traceroute => {
            table.add_row(Row::new(vec![
                TableCell::new_with_alignment("\tMax Hop", 1, Alignment::Left),
                TableCell::new_with_alignment(opt.max_hop, 1, Alignment::Left)
            ]));
            table.add_row(Row::new(vec![
                TableCell::new_with_alignment("Target:", 1, Alignment::Left)
            ]));
            for target in opt.targets {
                table.add_row(Row::new(vec![
                    TableCell::new_with_alignment("\tHost", 1, Alignment::Left),
                    TableCell::new_with_alignment(target.ip_addr, 1, Alignment::Left)
                ]));
            }
        },
        CommandType::UriScan => {},
        CommandType::DomainScan => {
            if opt.use_wordlist {
                table.add_row(Row::new(vec![
                    TableCell::new_with_alignment("\tWord List", 1, Alignment::Left),
                    TableCell::new_with_alignment(opt.wordlist_path, 1, Alignment::Left)
                ]));
            }
            table.add_row(Row::new(vec![
                TableCell::new_with_alignment("Target:", 1, Alignment::Left)
            ]));
            for target in opt.targets {
                table.add_row(Row::new(vec![
                    TableCell::new_with_alignment("\tDomain", 1, Alignment::Left),
                    TableCell::new_with_alignment(target.base_domain, 1, Alignment::Left)
                ]));
            }
        },
        CommandType::BatchScan => {},
        CommandType::PassiveScan => {},
    }
    println!("{}", table.render());
}

pub fn show_portscan_result(result: PortScanResult) {
    let mut table = Table::new();
    table.max_column_width = 60;
    table.separate_rows = false;
    table.style = TableStyle::blank();
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Scan Result:", 1, Alignment::Left)
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Host Info:", 1, Alignment::Left)
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("\tIP Address", 1, Alignment::Left),
        TableCell::new_with_alignment(result.host.ip_addr, 1, Alignment::Left)
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("\tHost Name", 1, Alignment::Left),
        TableCell::new_with_alignment(result.host.host_name, 1, Alignment::Left)
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("\tMAC Address", 1, Alignment::Left),
        TableCell::new_with_alignment(result.host.mac_addr , 1, Alignment::Left)
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("\tVendor Info", 1, Alignment::Left),
        TableCell::new_with_alignment(result.host.vendor_info , 1, Alignment::Left)
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("\tOS Name", 1, Alignment::Left),
        TableCell::new_with_alignment(result.host.os_name, 1, Alignment::Left)
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("\tCPE", 1, Alignment::Left),
        TableCell::new_with_alignment(result.host.cpe, 1, Alignment::Left)
    ]));
    println!("{}", table.render());
    let mut table = Table::new();
    table.max_column_width = 60;
    table.separate_rows = false;
    table.style = TableStyle::blank();
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Port Info:", 1, Alignment::Left)
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("\tNumber", 1, Alignment::Left),
        TableCell::new_with_alignment("Status", 1, Alignment::Left),
        TableCell::new_with_alignment("Service Name", 1, Alignment::Left),
        TableCell::new_with_alignment("Service Version", 1, Alignment::Left),
    ]));
    for port in result.ports {
        table.add_row(Row::new(vec![
            TableCell::new_with_alignment(format!("\t{}",port.port_number), 1, Alignment::Left),
            TableCell::new_with_alignment(port.port_status, 1, Alignment::Left),
            TableCell::new_with_alignment(port.service_name, 1, Alignment::Left),
            TableCell::new_with_alignment(port.service_version, 1, Alignment::Left),
        ]));
    }
    println!("{}", table.render());
    let mut table = Table::new();
    table.max_column_width = 60;
    table.separate_rows = false;
    table.style = TableStyle::blank();
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Performance:", 1, Alignment::Left)
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("\tPort Scan Time", 1, Alignment::Left),
        TableCell::new_with_alignment(format!("{:?}", result.port_scan_time), 1, Alignment::Left),
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("\tService Detection Time", 1, Alignment::Left),
        TableCell::new_with_alignment(format!("{:?}", result.service_detection_time), 1, Alignment::Left),
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("\tOS Detection Time", 1, Alignment::Left),
        TableCell::new_with_alignment(format!("{:?}", result.port_scan_time), 1, Alignment::Left),
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("\tTotal Scan Time", 1, Alignment::Left),
        TableCell::new_with_alignment(format!("{:?}", result.port_scan_time), 1, Alignment::Left),
    ]));
    println!("{}", table.render());
}

pub fn show_hostscan_result(result: HostScanResult) {
    let mut table = Table::new();
    table.max_column_width = 60;
    table.separate_rows = false;
    table.style = TableStyle::blank();
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Scan Result:", 1, Alignment::Left)
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("IP Address", 1, Alignment::Left),
        TableCell::new_with_alignment("Host Name", 1, Alignment::Left),
        TableCell::new_with_alignment("MAC Address", 1, Alignment::Left),
        TableCell::new_with_alignment("Vendor Info", 1, Alignment::Left),
        TableCell::new_with_alignment("OS (Guess)", 1, Alignment::Left),
        //TableCell::new_with_alignment("CPE", 1, Alignment::Left),
    ]));
    for host in result.hosts {
        table.add_row(Row::new(vec![
            TableCell::new_with_alignment(host.ip_addr, 1, Alignment::Left),
            TableCell::new_with_alignment(host.host_name, 1, Alignment::Left),
            TableCell::new_with_alignment(host.mac_addr , 1, Alignment::Left),
            TableCell::new_with_alignment(host.vendor_info , 1, Alignment::Left),
            TableCell::new_with_alignment(host.os_name, 1, Alignment::Left),
            //TableCell::new_with_alignment(host.cpe, 1, Alignment::Left),
        ]));
    }
    println!("{}", table.render());
    let mut table = Table::new();
    table.max_column_width = 60;
    table.separate_rows = false;
    table.style = TableStyle::blank();
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Performance:", 1, Alignment::Left)
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("\tHost Scan Time", 1, Alignment::Left),
        TableCell::new_with_alignment(format!("{:?}", result.host_scan_time), 1, Alignment::Left),
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("\tOS Detection Time", 1, Alignment::Left),
        TableCell::new_with_alignment(format!("{:?}", result.os_detection_time), 1, Alignment::Left),
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("\tTotal Scan Time", 1, Alignment::Left),
        TableCell::new_with_alignment(format!("{:?}", result.total_scan_time), 1, Alignment::Left),
    ]));
    println!("{}", table.render());
}

pub fn show_ping_result(result: PingStat) {
    let mut table = Table::new();
    table.max_column_width = 60;
    table.separate_rows = false;
    table.style = TableStyle::blank();
    /* table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Ping Result:", 1, Alignment::Left)
    ])); */
    println!();
    println!("Ping Result:");
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("SEQ", 1, Alignment::Left),
        TableCell::new_with_alignment("Protocol", 1, Alignment::Left),
        TableCell::new_with_alignment("IP Address", 1, Alignment::Left),
        TableCell::new_with_alignment("Host Name", 1, Alignment::Left),
        TableCell::new_with_alignment("Port Number", 1, Alignment::Left),
        TableCell::new_with_alignment("TTL", 1, Alignment::Left),
        TableCell::new_with_alignment("Hop", 1, Alignment::Left),
        TableCell::new_with_alignment("RTT", 1, Alignment::Left),
        //TableCell::new_with_alignment("CPE", 1, Alignment::Left),
    ]));
    for r in result.ping_results {
        table.add_row(Row::new(vec![
            TableCell::new_with_alignment(r.seq, 1, Alignment::Left),
            TableCell::new_with_alignment(r.protocol, 1, Alignment::Left),
            TableCell::new_with_alignment(r.ip_addr, 1, Alignment::Left),
            TableCell::new_with_alignment(r.host_name, 1, Alignment::Left),
            TableCell::new_with_alignment(format!("{:?}", r.port_number), 1, Alignment::Left),
            TableCell::new_with_alignment(r.ttl, 1, Alignment::Left),
            TableCell::new_with_alignment(r.hop, 1, Alignment::Left),
            TableCell::new_with_alignment(format!("{:?}", r.rtt), 1, Alignment::Left),
        ]));
    }
    println!("{}", table.render());

    let mut table = Table::new();
    table.max_column_width = 60;
    table.separate_rows = false;
    table.style = TableStyle::blank();
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Ping Stat:", 1, Alignment::Left)
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Probe Time", 1, Alignment::Left),
        TableCell::new_with_alignment("Transmitted", 1, Alignment::Left),
        TableCell::new_with_alignment("Received", 1, Alignment::Left),
        TableCell::new_with_alignment("Min", 1, Alignment::Left),
        TableCell::new_with_alignment("Avg", 1, Alignment::Left),
        TableCell::new_with_alignment("Max", 1, Alignment::Left),
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment(format!("{:?}", result.probe_time), 1, Alignment::Left),
        TableCell::new_with_alignment(result.transmitted_count, 1, Alignment::Left),
        TableCell::new_with_alignment(result.received_count, 1, Alignment::Left),
        TableCell::new_with_alignment(format!("{:?}", result.min), 1, Alignment::Left),
        TableCell::new_with_alignment(format!("{:?}", result.avg), 1, Alignment::Left),
        TableCell::new_with_alignment(format!("{:?}", result.max), 1, Alignment::Left),
    ]));
    println!("{}", table.render());
}

pub fn show_trace_result(result: TraceResult) {
    let mut table = Table::new();
    table.max_column_width = 60;
    table.separate_rows = false;
    table.style = TableStyle::blank();
    /* table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Trace Result:", 1, Alignment::Left)
    ])); */
    println!();
    println!("Trace Result:");
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("SEQ", 1, Alignment::Left),
        TableCell::new_with_alignment("IP Address", 1, Alignment::Left),
        TableCell::new_with_alignment("Host Name", 1, Alignment::Left),
        TableCell::new_with_alignment("Node Type", 1, Alignment::Left),
        TableCell::new_with_alignment("TTL", 1, Alignment::Left),
        TableCell::new_with_alignment("Hop", 1, Alignment::Left),
        TableCell::new_with_alignment("RTT", 1, Alignment::Left),
    ]));
    for node in result.nodes {
        table.add_row(Row::new(vec![
            TableCell::new_with_alignment(node.seq, 1, Alignment::Left),
            TableCell::new_with_alignment(node.ip_addr, 1, Alignment::Left),
            TableCell::new_with_alignment(node.host_name, 1, Alignment::Left),
            TableCell::new_with_alignment(format!("{:?}", node.node_type), 1, Alignment::Left),
            TableCell::new_with_alignment(format!("{:?}", node.ttl), 1, Alignment::Left),
            TableCell::new_with_alignment(format!("{:?}", node.hop), 1, Alignment::Left),
            TableCell::new_with_alignment(format!("{:?}", node.rtt), 1, Alignment::Left),
        ]));
    }
    println!("{}", table.render());
    let mut table = Table::new();
    table.max_column_width = 60;
    table.separate_rows = false;
    table.style = TableStyle::blank();
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Probe Time:", 1, Alignment::Left),
        TableCell::new_with_alignment(format!("{:?}", result.probe_time), 1, Alignment::Left),
    ]));
    println!("{}", table.render());
}

pub fn show_domainscan_result(result: DomainScanResult) {
    let mut table = Table::new();
    table.max_column_width = 60;
    table.separate_rows = false;
    table.style = TableStyle::blank();
    println!();
    println!("Scan Result:");
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Domain Name", 1, Alignment::Left),
        TableCell::new_with_alignment("IP Address", 1, Alignment::Left),
    ]));
    for domain in result.domains {
        for ip in domain.ips {
            table.add_row(Row::new(vec![
                TableCell::new_with_alignment(domain.domain_name.clone(), 1, Alignment::Left),
                TableCell::new_with_alignment(ip, 1, Alignment::Left),
            ]));
        }
    }
    println!("{}", table.render());
    let mut table = Table::new();
    table.max_column_width = 60;
    table.separate_rows = false;
    table.style = TableStyle::blank();
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Scan Time:", 1, Alignment::Left),
        TableCell::new_with_alignment(format!("{:?}", result.scan_time), 1, Alignment::Left),
    ]));
    println!("{}", table.render());
}
