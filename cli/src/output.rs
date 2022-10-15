use std::fmt::format;

use term_table::{Table, TableStyle};
use term_table::table_cell::{TableCell,Alignment};
use term_table::row::Row;
use nodemap_core::option::{CommandType, ScanOption, TargetInfo};
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
        TableCell::new_with_alignment("\tInterface Index", 1, Alignment::Left),
        TableCell::new_with_alignment(opt.interface_index, 1, Alignment::Left)
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("\tInterface Name", 1, Alignment::Left),
        TableCell::new_with_alignment(opt.interface_name, 1, Alignment::Left)
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
        },
        CommandType::BatchScan => {},
        CommandType::PassiveScan => {},
    }
    println!("{}", table.render());
}

pub fn show_portscan_result(_result: PortScanResult) {

}

pub fn show_hostscan_result(_result: HostScanResult) {

}
