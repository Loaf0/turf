#![allow(unused)]

use eframe::egui;
use std::sync::mpsc::{self, Receiver};
use pnet::datalink::{self, Channel::Ethernet, NetworkInterface};
use pnet::packet::{ethernet::EthernetPacket, ip::IpNextHeaderProtocols, ipv4::Ipv4Packet, Packet};
use std::fs;

// process module
mod process;
use crate::process::Process;

use winapi::um::winnt::{
    MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_READWRITE,
    PAGE_WRITECOPY,
};

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([1200.0, 800.0]),
        ..Default::default()
    };
    eframe::run_native("Turf", options, Box::new(|_cc| Ok(Box::<MyApp>::default())))
}

struct MyApp {
    selected_tab: Tab,

    // Packet inspection state
    packets: Vec<PacketInfo>,
    capturing: bool,
    packet_rx: Option<Receiver<PacketInfo>>,
    network_interfaces: Vec<NetworkInterface>,
    selected_interface_idx: usize,
    filter: String,
    selected_packet: Option<usize>,

    // Memory editing state
    process_pid: String,
    process: Option<Process>,
    regions: Vec<MEMORY_BASIC_INFORMATION>,
    locations: Vec<usize>,
    // process name search & matches
    process_search: String,
    matched_processes: Vec<(u32, String)>,
    selected_matched_idx: Option<usize>,
    // per-process matches when doing Find All
    process_matches: Vec<(u32, String, Vec<usize>)>,
    target_value: String,
    var_type: VarType,
    selected_location: Option<usize>,
    read_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VarType {
    U8,
    U16,
    U32,
    U64,
    I32,
    F32,
    F64,
    String,
    HexBytes,
}

impl Default for VarType {
    fn default() -> Self { VarType::I32 }
}

#[derive(PartialEq, Eq)]
enum Tab {
    PacketInspection,
    MemoryEditing,
    Settings,
}

impl Default for Tab {
    fn default() -> Self {
        Tab::PacketInspection
    }
}

impl Default for MyApp {
    fn default() -> Self {
        let interfaces = datalink::interfaces();
        Self {
            selected_tab: Tab::PacketInspection,
            packets: Vec::new(),
            capturing: false,
            packet_rx: None,
            network_interfaces: interfaces,
            selected_interface_idx: 0,
            filter: String::new(),
            selected_packet: None,

            process_pid: String::new(),
            process: None,
            regions: Vec::new(),
            locations: Vec::new(),
            process_search: String::new(),
            matched_processes: Vec::new(),
            selected_matched_idx: None,
            process_matches: Vec::new(),
            target_value: String::new(),
            var_type: VarType::default(),
            selected_location: None,
            read_bytes: Vec::new(),
        }
    }
}

impl eframe::App for MyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if let Some(rx) = &self.packet_rx {
            while let Ok(packet) = rx.try_recv() {
                self.packets.push(packet);
            }
        }

        egui::TopBottomPanel::top("tab_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if ui.selectable_label(self.selected_tab == Tab::PacketInspection, "Packet Inspection").clicked() {
                    self.selected_tab = Tab::PacketInspection;
                }
                if ui.selectable_label(self.selected_tab == Tab::MemoryEditing, "Memory Editing").clicked() {
                    self.selected_tab = Tab::MemoryEditing;
                }
                if ui.selectable_label(self.selected_tab == Tab::Settings, "Settings").clicked() {
                    self.selected_tab = Tab::Settings;
                }
            });
        });

        match self.selected_tab {
            Tab::PacketInspection => {
                egui::SidePanel::left("packet_list_panel").min_width(400.0).show(ctx, |ui| {
                    ui.heading("Packets");

                    // Network interface selector
                    ui.horizontal(|ui| {
                        ui.label("Interface:");
                        egui::ComboBox::from_id_salt("interface_selector")
                            .selected_text(
                                self.network_interfaces
                                    .get(self.selected_interface_idx)
                                    .map(|iface| iface.name.clone())
                                    .unwrap_or_else(|| "None".to_string())
                            )
                            .show_ui(ui, |cb_ui| {
                                for (i, iface) in self.network_interfaces.iter().enumerate() {
                                    let ip = iface.ips.get(0)
                                        .map(|ip| ip.to_string())
                                        .unwrap_or_else(|| "No IP".to_string());
                                    let label = format!("{} ({})", iface.name, ip);
                                    cb_ui.selectable_value(&mut self.selected_interface_idx, i, label);
                                }
                            });
                    });

                    // Buttons row
                    ui.horizontal(|ui| {
                        if ui.button("Start").clicked() {
                            if !self.capturing {
                                self.capturing = true;
                                let (tx, rx) = mpsc::channel();
                                self.packet_rx = Some(rx);

                                let interface = self.network_interfaces[self.selected_interface_idx].clone();
                                std::thread::spawn(move || {
                                    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
                                        Ok(Ethernet(_tx, rx)) => (_tx, rx),
                                        Ok(_) => panic!("Unhandled channel type"),
                                        Err(e) => panic!("Failed to create datalink channel: {}", e),
                                    };

                                    while let Ok(packet) = rx.next() {
                                        let summary = format!("Packet: {} bytes", packet.len());
                                        let info = PacketInfo {
                                            summary,
                                            data: packet.to_vec(),
                                        };
                                        let _ = tx.send(info);
                                    }
                                });
                            }
                        }
                        if ui.button("Pause").clicked() {
                            self.capturing = false;
                            self.packet_rx = None;
                        }
                        if ui.button("Clear").clicked() {
                            self.capturing = false;
                            self.packets.clear();
                            self.packet_rx = None;
                        }
                    });

                    // Filter row
                    ui.horizontal(|ui| {
                        ui.label("Filter:");
                        ui.text_edit_singleline(&mut self.filter);
                    });
                    ui.separator();

                    // Packet table
                    ui.push_id("packet_list_scroll", |ui| {
                        egui::ScrollArea::vertical().show(ui, |ui| {
                            egui::Grid::new("packet_table")
                            .striped(true)
                            .show(ui, |ui| {
                                ui.label("Seq");
                                ui.label("Source");
                                ui.label("Destination");
                                ui.label("Protocol");
                                ui.label("Length");
                                ui.end_row();

                                for (idx, packet) in self.packets.iter().enumerate() {
                                    let (src, dst, proto) = parse_packet_info(&packet.data);
                                    let filter = self.filter.to_lowercase();
                                    if !filter.is_empty()
                                        && !src.to_lowercase().contains(&filter)
                                        && !dst.to_lowercase().contains(&filter)
                                        && !proto.to_lowercase().contains(&filter)
                                    {
                                        continue;
                                    }
                                    let selected = Some(idx) == self.selected_packet;
                                    if ui.selectable_label(selected, format!("{}", idx + 1)).clicked() {
                                        self.selected_packet = Some(idx);
                                    }
                                    ui.label(src);
                                    ui.label(dst);
                                    ui.label(proto);
                                    ui.label(format!("{}", packet.data.len()));
                                    ui.end_row();
                                }
                            });
                        });
                    });

                });

                egui::CentralPanel::default().show(ctx, |ui| {
                    ui.heading("Packet Details");
                    if let Some(idx) = self.selected_packet {
                        if let Some(packet) = self.packets.get(idx) {
                            if ui.button("Resend Packet").clicked() {
                                if let Some(interface) = self.network_interfaces.get(self.selected_interface_idx) {
                                    if let Ok(pnet::datalink::Channel::Ethernet(mut tx, _)) = pnet::datalink::channel(interface, Default::default()) {
                                        let _ = tx.send_to(&packet.data, None);
                                    }
                                }
                            }

                            if ui.button("Save Packet Contents").clicked() {
                                let seq = idx + 1;
                                let contents = format!("{:02X?}", &packet.data);
                                let _ = fs::create_dir_all("packets");
                                fs::write(format!("packets/packet{}.txt", seq), contents.as_bytes()).unwrap();
                            }

                            ui.label(format!("Summary: "));
                            ui.label(format!("Length: {} bytes", packet.data.len()));
                            ui.label(format!("Data (hex): {:02X?}", &packet.data));
                            let text = String::from_utf8_lossy(&packet.data);
                            ui.label("Text:");
                            ui.add(egui::TextEdit::multiline(&mut text.clone()).font(egui::TextStyle::Monospace).desired_rows(4).lock_focus(true));
                        } else {
                            ui.label("No packet selected.");
                        }
                    } else {
                        ui.label("Select a packet to view details.");
                    }
                });
            }
            Tab::MemoryEditing => {
                egui::CentralPanel::default().show(ctx, |ui| {
                    ui.heading("Memory Editing");

                    ui.horizontal(|ui| {
                        ui.vertical(|ui| {
                            ui.label("Search process by name:");
                            ui.horizontal(|ui| {
                                ui.text_edit_singleline(&mut self.process_search);
                                if ui.button("Find").clicked() {
                                    match crate::process::Process::list_processes() {
                                        Ok(list) => {
                                            let needle = self.process_search.to_lowercase();
                                            self.matched_processes = list.into_iter()
                                                .filter(|(_pid, name)| name.to_lowercase().contains(&needle))
                                                .collect();
                                            self.selected_matched_idx = None;
                                        }
                                        Err(e) => {
                                            eprintln!("Failed to list processes: {}", e);
                                            self.matched_processes.clear();
                                        }
                                    }
                                }
                                if ui.button("Find All Processes").clicked() {
                                    if let Some(bytes) = parse_target_bytes(self.var_type, &self.target_value) {
                                        self.process_matches.clear();
                                        for (pid, name) in &self.matched_processes {
                                            if let Ok(p) = Process::open(*pid) {
                                                match p.memory_regions() {
                                                    Ok(regs) => {
                                                        let mut found = Vec::new();
                                                        for r in regs.iter() {
                                                            if let Ok(mem) = p.read_memory(r.BaseAddress as _, r.RegionSize) {
                                                                for (off, window) in mem.windows(bytes.len()).enumerate() {
                                                                    if window == bytes.as_slice() {
                                                                        found.push(r.BaseAddress as usize + off);
                                                                    }
                                                                }
                                                            }
                                                        }
                                                        if !found.is_empty() {
                                                            self.process_matches.push((*pid, name.clone(), found));
                                                        }
                                                    }
                                                    Err(e) => eprintln!("Regions error for {}: {}", pid, e),
                                                }
                                            }
                                        }
                                    } else {
                                        eprintln!("Failed to parse target value for Find All Processes");
                                    }
                                }
                            });

                            ui.separator();
                            ui.label("Matches:");
                            ui.push_id("matched_processes_scroll", |ui| {
                                egui::ScrollArea::vertical().max_height(120.0).show(ui, |ui| {
                                    for (i, (pid, name)) in self.matched_processes.iter().enumerate() {
                                        if ui.selectable_label(Some(i) == self.selected_matched_idx, format!("{} - {}", pid, name)).clicked() {
                                            self.selected_matched_idx = Some(i);
                                            if let Ok(p) = Process::open(*pid) {
                                                self.process = Some(p);
                                                self.process_pid = pid.to_string();
                                                self.regions.clear();
                                                self.locations.clear();
                                                self.read_bytes.clear();
                                                self.selected_location = None;
                                            }
                                        }
                                    }
                                });
                            });
                        });

                        ui.separator();

                        ui.vertical(|ui| {
                            ui.label("Or open by PID:");
                            ui.horizontal(|ui| {
                                ui.label("PID:");
                                ui.text_edit_singleline(&mut self.process_pid);
                                if ui.button("Open").clicked() {
                                    if let Ok(pid) = self.process_pid.trim().parse::<u32>() {
                                        match Process::open(pid) {
                                            Ok(p) => {
                                                eprintln!("Opened PID {}", pid);
                                                self.process = Some(p);
                                                self.regions.clear();
                                                self.locations.clear();
                                                self.read_bytes.clear();
                                                self.selected_location = None;
                                            }
                                            Err(e) => {
                                                eprintln!("Failed to open {}: {}", pid, e);
                                                self.process = None;
                                            }
                                        }
                                    } else {
                                        eprintln!("Invalid PID: {}", self.process_pid);
                                    }
                                }

                                if ui.button("Get Regions").clicked() {
                                    if let Some(proc_ref) = &self.process {
                                        match proc_ref.memory_regions() {
                                            Ok(regs) => {
                                                let mask = PAGE_EXECUTE_READWRITE
                                                    | PAGE_EXECUTE_WRITECOPY
                                                    | PAGE_READWRITE
                                                    | PAGE_WRITECOPY;
                                                self.regions = regs.into_iter().filter(|r| (r.Protect & mask) != 0).collect();
                                                eprintln!("Memory regions found : {}", self.regions.len());
                                            }
                                            Err(e) => {
                                                eprintln!("Failed to get memory regions: {}", e);
                                                self.regions.clear();
                                            }
                                        }
                                        self.locations.clear();
                                    }
                                }
                            });
                        });
                    });

                    ui.separator();

                    ui.horizontal(|ui| {
                        ui.label("Type:");
                        egui::ComboBox::from_id_salt("var_type_cb").selected_text(format!("{:?}", self.var_type)).show_ui(ui, |cb| {
                            cb.selectable_value(&mut self.var_type, VarType::U8, "u8");
                            cb.selectable_value(&mut self.var_type, VarType::U16, "u16");
                            cb.selectable_value(&mut self.var_type, VarType::U32, "u32");
                            cb.selectable_value(&mut self.var_type, VarType::U64, "u64");
                            cb.selectable_value(&mut self.var_type, VarType::I32, "i32");
                            cb.selectable_value(&mut self.var_type, VarType::F32, "f32");
                            cb.selectable_value(&mut self.var_type, VarType::F64, "f64");
                            cb.selectable_value(&mut self.var_type, VarType::String, "string");
                            cb.selectable_value(&mut self.var_type, VarType::HexBytes, "hex bytes");
                        });

                        ui.label("Target:");
                        ui.text_edit_singleline(&mut self.target_value);

                        if ui.button("Initial Scan").clicked() {
                            if let Some(bytes) = parse_target_bytes(self.var_type, &self.target_value) {
                                self.initial_scan(&bytes);
                            } else {
                                eprintln!("Failed to parse target value for initial scan");
                            }
                        }

                        if ui.button("Rescan").clicked() {
                            if let Some(bytes) = parse_target_bytes(self.var_type, &self.target_value) {
                                self.rescan_locations(&bytes);
                            } else {
                                eprintln!("Failed to parse target value for rescan");
                            }
                        }
                    });

                    ui.separator();

                    ui.label(format!("Found locations: {}", self.locations.len()));
                    ui.push_id("locations_scroll", |ui| {
                        egui::ScrollArea::vertical().max_height(160.0).show(ui, |ui| {
                            for (i, &addr) in self.locations.iter().enumerate() {
                                let label = format!("{}: 0x{:X}", i, addr);
                                if ui.selectable_label(Some(i) == self.selected_location.map(|n| n), label).clicked() {
                                    self.selected_location = Some(i);
                                    if let Some(proc_ref) = &self.process {
                                        match proc_ref.read_memory(addr, 64) {
                                            Ok(data) => self.read_bytes = data,
                                            Err(e) => {
                                                eprintln!("Failed to read at 0x{:X}: {}", addr, e);
                                                self.read_bytes.clear();
                                            }
                                        }
                                    }
                                }
                            }
                        });
                    });

                    ui.separator();
                    ui.label("Process matches (Find All):");
                    ui.push_id("process_matches_scroll", |ui| {
                        egui::ScrollArea::vertical().max_height(160.0).show(ui, |ui| {
                            for (pid, name, addrs) in self.process_matches.iter() {
                                ui.collapsing(format!("{} - {} ({} hits)", pid, name, addrs.len()), |ui| {
                                    for a in addrs.iter() {
                                        if ui.button(format!("0x{:X}", a)).clicked() {
                                            // open this process and show this address
                                            if let Ok(p) = Process::open(*pid) {
                                                self.process = Some(p);
                                                self.process_pid = pid.to_string();
                                                self.locations = addrs.clone();
                                                self.selected_location = Some(0);
                                                if let Some(addr) = self.locations.get(0) {
                                                    match self.process.as_ref().unwrap().read_memory(*addr, 64) {
                                                        Ok(data) => self.read_bytes = data,
                                                        Err(e) => eprintln!("Failed to read: {}", e),
                                                    }
                                                }
                                            }
                                        }
                                    }
                                });
                            }
                        });
                    });

                    ui.separator();
                    ui.label("Preview bytes (hex):");
                    let mut preview = format_hex(&self.read_bytes);
                    ui.add(egui::TextEdit::multiline(&mut preview).font(egui::TextStyle::Monospace).desired_rows(6).lock_focus(true));
                });
            }
            Tab::Settings => {
                egui::CentralPanel::default().show(ctx, |ui| {
                    ui.heading("Settings");
                    ui.label("You can change things here.");
                });
            }
        }
    }
}

struct PacketInfo {
    summary: String,
    data: Vec<u8>,
}

// Helper to parse Ethernet/IPv4 info for display
fn parse_packet_info(data: &[u8]) -> (String, String, String) {
    if let Some(eth) = EthernetPacket::new(data) {
        let proto = format!("{:?}", eth.get_ethertype());
        if eth.get_ethertype() == pnet::packet::ethernet::EtherTypes::Ipv4 {
            if let Some(ipv4) = Ipv4Packet::new(eth.payload()) {
                let proto_name = match ipv4.get_next_level_protocol() {
                    IpNextHeaderProtocols::Tcp => "TCP",
                    IpNextHeaderProtocols::Udp => "UDP",
                    IpNextHeaderProtocols::Icmp => "ICMP",
                    IpNextHeaderProtocols::Igmp => "IGMP",
                    other => return (
                        ipv4.get_source().to_string(),
                        ipv4.get_destination().to_string(),
                        format!("{:?}", other),
                    ),
                };
                return (
                    ipv4.get_source().to_string(),
                    ipv4.get_destination().to_string(),
                    proto_name.to_string(),
                );
            }
        }
        (
            eth.get_source().to_string(),
            eth.get_destination().to_string(),
            proto,
        )
    } else {
        ("?".into(), "?".into(), "?".into())
    }
}

// scanning helpers
impl MyApp {
    fn initial_scan(&mut self, target_bytes: &[u8]) {
        self.locations.clear();
        let process = match &self.process {
            Some(p) => p,
            None => {
                eprintln!("No process opened for initial scan.");
                return;
            }
        };

        for region in &self.regions {
            match process.read_memory(region.BaseAddress as _, region.RegionSize) {
                Ok(memory) => {
                    for (offset, window) in memory.windows(target_bytes.len()).enumerate() {
                        if window == target_bytes {
                            self.locations.push(region.BaseAddress as usize + offset);
                        }
                    }
                }
                Err(err) => {
                    eprintln!("Failed to read {} bytes at {:?}: {}", region.RegionSize, region.BaseAddress, err);
                }
            }
        }
        eprintln!("Initial scan completed. {} locations", self.locations.len());
    }

    fn rescan_locations(&mut self, target_bytes: &[u8]) {
        let process = match &self.process {
            Some(p) => p,
            None => {
                eprintln!("No process opened for rescan.");
                return;
            }
        };

        self.locations.retain(|&addr| match process.read_memory(addr, target_bytes.len()) {
            Ok(memory) => memory == target_bytes,
            Err(_) => false,
        });
        eprintln!("Rescan completed. {} locations remain", self.locations.len());
    }
}

fn format_hex(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::from("");
    }
    bytes.iter().map(|b| format!("{:02X} ", b)).collect::<String>()
}

fn parse_target_bytes(var_type: VarType, s: &str) -> Option<Vec<u8>> {
    let t = s.trim();
    if t.is_empty() {
        return None;
    }
    match var_type {
        VarType::U8 => {
            let v = if t.starts_with("0x") { u8::from_str_radix(&t[2..], 16).ok()? } else { t.parse::<u8>().ok()? };
            Some(vec![v])
        }
        VarType::U16 => {
            let v = if t.starts_with("0x") { u16::from_str_radix(&t[2..], 16).ok()? } else { t.parse::<u16>().ok()? };
            Some(v.to_ne_bytes().to_vec())
        }
        VarType::U32 => {
            let v = if t.starts_with("0x") { u32::from_str_radix(&t[2..], 16).ok()? } else { t.parse::<u32>().ok()? };
            Some(v.to_ne_bytes().to_vec())
        }
        VarType::U64 => {
            let v = if t.starts_with("0x") { u64::from_str_radix(&t[2..], 16).ok()? } else { t.parse::<u64>().ok()? };
            Some(v.to_ne_bytes().to_vec())
        }
        VarType::I32 => {
            let v = t.parse::<i32>().ok()?;
            Some(v.to_ne_bytes().to_vec())
        }
        VarType::F32 => {
            let v = t.parse::<f32>().ok()?;
            Some(v.to_ne_bytes().to_vec())
        }
        VarType::F64 => {
            let v = t.parse::<f64>().ok()?;
            Some(v.to_ne_bytes().to_vec())
        }
        VarType::String => {
            Some(t.as_bytes().to_vec())
        }
        VarType::HexBytes => {
            // Accept hex string with or without spaces, e.g. "DE AD BE EF" or "DEADBEEF" or "0xDEADBEEF"
            let mut s = t.replace(" ", "");
            if s.starts_with("0x") || s.starts_with("0X") { s = s[2..].to_string(); }
            if s.len() % 2 != 0 { return None; }
            let mut out = Vec::with_capacity(s.len()/2);
            for i in (0..s.len()).step_by(2) {
                let byte = u8::from_str_radix(&s[i..i+2], 16).ok()?;
                out.push(byte);
            }
            Some(out)
        }
    }
}
