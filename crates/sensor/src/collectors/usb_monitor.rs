//! USB device monitoring collector.
//!
//! Monitors udev events for USB device insertion/removal via /dev/input
//! and /sys/bus/usb/devices enumeration. Detects BadUSB, rubber ducky,
//! unauthorized storage devices.
//!
//! For servers, ANY USB insertion is suspicious and worth alerting on.

use chrono::Utc;
use innerwarden_core::entities::EntityRef;
use innerwarden_core::event::{Event, Severity};
use tokio::sync::mpsc;
use tracing::info;

/// Known suspicious USB device indicators.
const SUSPICIOUS_VENDORS: &[&str] = &[
    "hak5",      // Rubber Ducky, Bash Bunny
    "0x1337",    // Common attacker vendor ID spoof
    "ducky",     // Rubber Ducky variants
    "teensy",    // Teensy board (HID attack tool)
    "digispark", // Digispark (cheap HID attack)
];

/// Run USB monitoring by polling /sys/bus/usb/devices.
pub async fn run(tx: mpsc::Sender<Event>, host_id: String, interval_secs: u64) {
    info!("usb_monitor: starting (interval: {interval_secs}s)");

    let mut known_devices: std::collections::HashSet<String> = std::collections::HashSet::new();

    // Initial scan
    let initial = scan_usb_devices();
    for dev in &initial {
        known_devices.insert(dev.path.clone());
    }
    info!("usb_monitor: baseline {} USB devices", known_devices.len());

    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(interval_secs)).await;

        let current = scan_usb_devices();
        let now = Utc::now();

        // Detect new devices
        for dev in &current {
            if !known_devices.contains(&dev.path) {
                known_devices.insert(dev.path.clone());

                let severity = classify_device(dev);
                let mut signals: Vec<String> = Vec::new();

                if dev.device_class == "03" || dev.interface_class.contains(&"03".to_string()) {
                    signals.push("hid_device".into()); // HID = keyboard/mouse = possible BadUSB
                }
                if dev.device_class == "08" || dev.interface_class.contains(&"08".to_string()) {
                    signals.push("mass_storage".into());
                }
                let vendor_lower = dev.vendor_name.to_lowercase();
                if SUSPICIOUS_VENDORS.iter().any(|s| vendor_lower.contains(s)) {
                    signals.push("suspicious_vendor".into());
                }
                if dev.serial.is_empty() || dev.serial == "0" {
                    signals.push("no_serial".into()); // Spoofed devices often lack serial
                }

                let event = Event {
                    ts: now,
                    host: host_id.clone(),
                    source: "usb_monitor".into(),
                    kind: "hardware.usb_inserted".into(),
                    severity,
                    summary: format!(
                        "USB device inserted: {} {} (vendor:{}, product:{})",
                        dev.vendor_name, dev.product_name, dev.vendor_id, dev.product_id
                    ),
                    details: serde_json::json!({
                        "action": "add",
                        "vendor_id": dev.vendor_id,
                        "product_id": dev.product_id,
                        "vendor_name": dev.vendor_name,
                        "product_name": dev.product_name,
                        "serial": dev.serial,
                        "device_class": dev.device_class,
                        "interface_classes": dev.interface_class,
                        "bus": dev.bus,
                        "port": dev.port,
                        "signals": signals,
                    }),
                    tags: vec!["hardware".into(), "usb".into()],
                    entities: vec![EntityRef::path(dev.path.clone())],
                };

                let _ = tx.send(event).await;
            }
        }

        // Detect removed devices
        let current_paths: std::collections::HashSet<String> =
            current.iter().map(|d| d.path.clone()).collect();
        let removed: Vec<String> = known_devices
            .iter()
            .filter(|p| !current_paths.contains(*p))
            .cloned()
            .collect();

        for path in &removed {
            known_devices.remove(path);

            let event = Event {
                ts: now,
                host: host_id.clone(),
                source: "usb_monitor".into(),
                kind: "hardware.usb_removed".into(),
                severity: Severity::Info,
                summary: format!("USB device removed: {path}"),
                details: serde_json::json!({
                    "action": "remove",
                    "path": path,
                }),
                tags: vec!["hardware".into(), "usb".into()],
                entities: vec![EntityRef::path(path.clone())],
            };

            let _ = tx.send(event).await;
        }
    }
}

#[derive(Debug)]
struct UsbDevice {
    path: String,
    vendor_id: String,
    product_id: String,
    vendor_name: String,
    product_name: String,
    serial: String,
    device_class: String,
    interface_class: Vec<String>,
    bus: String,
    port: String,
}

fn scan_usb_devices() -> Vec<UsbDevice> {
    let mut devices = Vec::new();
    let usb_path = std::path::Path::new("/sys/bus/usb/devices");

    let Ok(entries) = std::fs::read_dir(usb_path) else {
        return devices;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();

        // Skip interfaces (contain :), only want devices (like 1-1, 2-1.3)
        if name.contains(':') || name == "usb1" || name == "usb2" {
            continue;
        }

        let read = |file: &str| -> String {
            std::fs::read_to_string(path.join(file))
                .map(|s| s.trim().to_string())
                .unwrap_or_default()
        };

        let vendor_id = read("idVendor");
        if vendor_id.is_empty() {
            continue; // Not a real USB device entry
        }

        // Collect interface classes
        let mut interface_class = Vec::new();
        if let Ok(intf_entries) = std::fs::read_dir(&path) {
            for ie in intf_entries.flatten() {
                let ie_name = ie.file_name().to_string_lossy().to_string();
                if ie_name.contains(':') {
                    let ic = std::fs::read_to_string(ie.path().join("bInterfaceClass"))
                        .map(|s| s.trim().to_string())
                        .unwrap_or_default();
                    if !ic.is_empty() {
                        interface_class.push(ic);
                    }
                }
            }
        }

        devices.push(UsbDevice {
            path: path.to_string_lossy().to_string(),
            vendor_id,
            product_id: read("idProduct"),
            vendor_name: read("manufacturer"),
            product_name: read("product"),
            serial: read("serial"),
            device_class: read("bDeviceClass"),
            interface_class,
            bus: read("busnum"),
            port: read("devpath"),
        });
    }

    devices
}

fn classify_device(dev: &UsbDevice) -> Severity {
    // Suspicious vendor first (highest priority)
    let vendor_lower = dev.vendor_name.to_lowercase();
    if SUSPICIOUS_VENDORS.iter().any(|s| vendor_lower.contains(s)) {
        return Severity::Critical;
    }
    // HID device on a server = very suspicious (possible BadUSB)
    if dev.device_class == "03" || dev.interface_class.contains(&"03".to_string()) {
        return Severity::High;
    }
    // Mass storage = potential data exfiltration
    if dev.device_class == "08" || dev.interface_class.contains(&"08".to_string()) {
        return Severity::High;
    }
    Severity::Medium
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_hid() {
        let dev = UsbDevice {
            path: "/sys/bus/usb/devices/1-1".into(),
            vendor_id: "0x1234".into(),
            product_id: "0x5678".into(),
            vendor_name: "Generic".into(),
            product_name: "Keyboard".into(),
            serial: String::new(),
            device_class: "03".into(),
            interface_class: vec![],
            bus: "1".into(),
            port: "1".into(),
        };
        assert_eq!(classify_device(&dev), Severity::High);
    }

    #[test]
    fn test_classify_hak5() {
        let dev = UsbDevice {
            path: "/sys/bus/usb/devices/1-2".into(),
            vendor_id: "0x1337".into(),
            product_id: "0x0001".into(),
            vendor_name: "Hak5 LLC".into(),
            product_name: "USB Rubber Ducky".into(),
            serial: String::new(),
            device_class: "00".into(),
            interface_class: vec!["03".into()],
            bus: "1".into(),
            port: "2".into(),
        };
        assert_eq!(classify_device(&dev), Severity::Critical);
    }
}
