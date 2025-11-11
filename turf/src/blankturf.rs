#![allow(unused)]

use eframe::egui;
use std::sync::mpsc::{self, Receiver};
use pnet::datalink::{self, Channel::Ethernet, NetworkInterface};
use pnet::packet::{ethernet::EthernetPacket, ip::IpNextHeaderProtocols, ipv4::Ipv4Packet, Packet};
use std::fs;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([1200.0, 800.0]),
        ..Default::default()
    };
    eframe::run_native("Turf", options, Box::new(|_cc| Ok(Box::<MyApp>::default())))
}

struct MyApp {
    selected_tab: Tab,
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
        }
    }
}

impl eframe::App for MyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::TopBottomPanel::top("tab_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if ui.selectable_label(self.selected_tab == Tab::MemoryEditing, "Memory Editing").clicked() {
                    self.selected_tab = Tab::MemoryEditing;
                }
                if ui.selectable_label(self.selected_tab == Tab::PacketInspection, "Packet Inspection").clicked() {
                    self.selected_tab = Tab::PacketInspection;
                }
                if ui.selectable_label(self.selected_tab == Tab::Settings, "Settings").clicked() {
                    self.selected_tab = Tab::Settings;
                }
            });
        });
        

        match self.selected_tab {
            Tab::MemoryEditing => {
                egui::CentralPanel::default().show(ctx, |ui| {
                    ui.heading("Memory Editing");
                    ui.label("Here you can edit process memory.");
                });
            }
            Tab::PacketInspection => {
                egui::CentralPanel::default().show(ctx, |ui| {
                    ui.heading("Inspect Packets");
                    ui.label("Here you can edit process memory.");
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