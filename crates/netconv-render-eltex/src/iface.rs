use netconv_core::ir::*;
use netconv_core::report::ConversionReport;
use crate::security::classify_zone;

pub fn render_interfaces(cfg: &NetworkConfig, out: &mut Vec<String>, report: &mut ConversionReport) {
    // Fix: дедупликация по ESR имени — GE и FE могут маппиться в одно имя
    let mut seen_esr_names: std::collections::HashSet<String> = std::collections::HashSet::new();
    // Счётчик для GE портов — после FE портов
    let fe_count = cfg.interfaces.iter()
        .filter(|i| i.name.kind == InterfaceKind::FastEthernet)
        .count() as u32;

    for iface in &cfg.interfaces {
        let esr_name = ios_to_esr_ifname_with_offset(iface, fe_count);
        let base_name = esr_name.split('!').next().unwrap_or(esr_name.as_str()).trim().to_string();

        if seen_esr_names.contains(&base_name) {
            out.push(format!("! SKIPPED DUPLICATE: {} → {} (already generated)",
                iface.name.original, base_name));
            report.add_approximate(
                "interface.duplicate",
                &format!("interface {}", iface.name.original),
                &format!("# duplicate of {}", base_name),
                &format!("Interface {} maps to same ESR port as a previous interface. \
                         Verify port mapping manually.", iface.name.original),
            );
            continue;
        }
        seen_esr_names.insert(base_name.clone());

        render_interface(iface, &esr_name, cfg, out, report);
    }

    // LOST SEMANTICS блок
    render_lost_l2_semantics(cfg, out, report);
}

fn render_interface(
    iface: &Interface,
    esr_name: &str,
    cfg: &NetworkConfig,
    out: &mut Vec<String>,
    report: &mut ConversionReport,
) {
    let src_block = format!("interface {}", iface.name.original);
    let _base_name = esr_name.split('!').next().unwrap_or(esr_name).trim();

    out.push("!".to_string());
    out.push(format!("interface {}", esr_name));

    if let Some(desc) = &iface.description {
        out.push(format!(" description {}", desc));
        report.add_exact("interface.description", &src_block, &format!("description {}", desc));
    }

    // Security zone — из classify_zone
    let zone = classify_zone(iface, cfg);
    let zone_name = zone.zone.as_str();
    out.push(format!(" security-zone {}", zone_name));

    let zone_note = format!("classified as {}: {}", zone_name, zone.reason);
    report.add_approximate(
        "interface.security_zone",
        &format!("# (no zone in Cisco IOS for {})", iface.name.original),
        &format!("security-zone {}", zone_name),
        &format!("ESR: security-zone mandatory. {}.", zone_note),
    );

    // IP addresses (CIDR)
    for (i, addr) in iface.addresses.iter().enumerate() {
        if i == 0 && !addr.secondary {
            out.push(format!(" ip address {}", addr.prefix));
            report.add_exact(
                "interface.ip",
                &format!("ip address {} ({})", addr.prefix, iface.name.original),
                &format!("ip address {}", addr.prefix),
            );
        } else {
            out.push(format!(" ip address {}", addr.prefix));
            report.add_approximate(
                "interface.ip.secondary",
                &format!("ip address {} secondary", addr.prefix),
                &format!("ip address {}", addr.prefix),
                "ESR: multiple ip address without 'secondary' keyword",
            );
        }
    }

    if iface.shutdown {
        out.push(" shutdown".to_string());
        report.add_exact("interface.shutdown", &src_block, "shutdown");
    }

    if let Some(mtu) = iface.mtu {
        out.push(format!(" mtu {}", mtu));
        report.add_exact("interface.mtu", &src_block, &format!("mtu {}", mtu));
    }

    for helper in &iface.helper_addresses {
        out.push(format!(" ip helper-address {}", helper));
        report.add_approximate(
            "interface.helper",
            &format!("ip helper-address {}", helper),
            &format!("ip helper-address {}", helper),
            "ESR: ip helper-address syntax matches Cisco",
        );
    }

    if let Some(acl_in) = &iface.acl_in {
        out.push(format!(" ip access-group {} in", acl_in));
        report.add_approximate("interface.acl",
            &format!("ip access-group {} in", acl_in),
            &format!("ip access-group {} in", acl_in),
            "ESR: ip access-group syntax matches Cisco",
        );
    }
    if let Some(acl_out) = &iface.acl_out {
        out.push(format!(" ip access-group {} out", acl_out));
        report.add_approximate("interface.acl",
            &format!("ip access-group {} out", acl_out),
            &format!("ip access-group {} out", acl_out),
            "ESR: ip access-group syntax matches Cisco",
        );
    }

    if let Some(ospf) = &iface.ospf {
        let area_str = ospf_area_str(&ospf.area);
        out.push(format!(" ip ospf instance {}", ospf.process_id));
        out.push(format!(" ip ospf area {}", area_str));
        out.push(" ip ospf".to_string());
        report.add_approximate(
            "ospf.interface",
            &format!("ip ospf {} area {}", ospf.process_id, area_str),
            &format!("ip ospf instance {} / area {} / ip ospf", ospf.process_id, area_str),
            "ESR: OSPF enabled via ip ospf instance + area + ip ospf (enable)",
        );
        if let Some(cost) = ospf.cost {
            out.push(format!(" ip ospf cost {}", cost));
        }
    }

    for hsrp in &iface.hsrp {
        render_hsrp_as_vrrp(hsrp, out, report);
    }

    out.push(" exit".to_string());
    out.push(String::new());
}

/// Блок LOST SEMANTICS — явно показываем что потеряно
fn render_lost_l2_semantics(cfg: &NetworkConfig, out: &mut Vec<String>, report: &mut ConversionReport) {
    // Собираем L2 информацию из конфига
    let has_vlans = !cfg.vlans.is_empty();
    let has_voice_vlan = cfg.interfaces.iter().any(|i| i.voice_vlan.is_some());
    let has_storm_control = cfg.interfaces.iter().any(|i| i.storm_control.is_some());
    let has_stp = cfg.stp.is_some();
    let has_l2_ifaces = cfg.interfaces.iter().any(|i| i.l2.is_some());

    if !has_vlans && !has_voice_vlan && !has_storm_control && !has_stp && !has_l2_ifaces {
        return;
    }

    out.push("!".to_string());
    out.push("! ============================================================".to_string());
    out.push("! LOST SEMANTICS: L2 features not supported on Eltex ESR".to_string());
    out.push("! ============================================================".to_string());

    // VLAN segmentation
    if has_vlans || has_l2_ifaces {
        out.push("!".to_string());
        out.push("! VLAN segmentation detected in source config:".to_string());
        for vlan in &cfg.vlans {
            match &vlan.name {
                Some(name) => out.push(format!("!   VLAN {:>4}: {}", vlan.id, name)),
                None       => out.push(format!("!   VLAN {:>4}: (no name)", vlan.id)),
            }
        }
        // Voice VLANs
        let voice_vlans: Vec<u16> = cfg.interfaces.iter()
            .filter_map(|i| i.voice_vlan)
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter().collect();
        for vv in &voice_vlans {
            out.push(format!("!   VLAN {:>4}: (voice VLAN)", vv));
        }
        out.push("!".to_string());
        out.push("! ESR cannot represent L2 VLAN segmentation directly.".to_string());
        out.push("!".to_string());
        out.push("! MIGRATION STRATEGY:".to_string());
        out.push("!   Option 1 (recommended): Keep L2 switching on external switch (Eltex MES)".to_string());
        out.push("!     ESR acts as L3 gateway, MES handles VLANs".to_string());
        out.push("!".to_string());
        out.push("!   Option 2: VLAN subinterfaces on ESR (if inter-VLAN routing needed):".to_string());

        // Генерим пример subinterface для каждого VLAN
        for vlan in cfg.vlans.iter().take(3) {
            out.push(format!("!     interface gigabitethernet 1/0/X.{}",  vlan.id));
            out.push(format!("!      encapsulation dot1q {}", vlan.id));
            out.push(format!("!      ip address <IP>/<PREFIX>  ! was VLAN {}: {}",
                vlan.id, vlan.name.as_deref().unwrap_or("unnamed")));
            out.push("!      security-zone LAN".to_string());
            out.push("!      exit".to_string());
        }
        if cfg.vlans.len() > 3 {
            out.push(format!("!     ... and {} more VLANs", cfg.vlans.len() - 3));
        }

        report.add_manual(
            "vlan.lost",
            &format!("{} VLANs not migrated", cfg.vlans.len()),
            "ESR does not support L2 VLAN segmentation. \
             Use external switch (Eltex MES) or VLAN subinterfaces.",
            Some("interface gigabitethernet X.VLAN / encapsulation dot1q VLAN / ip address ..."),
        );
    }

    // Storm-control
    if has_storm_control {
        out.push("!".to_string());
        out.push("! LOST CONTROL: storm-control settings not migrated.".to_string());
        out.push("!   ESR does not support L2 storm-control.".to_string());
        out.push("!   Ensure broadcast/multicast protection is handled upstream (on switch).".to_string());
        report.add_manual(
            "storm_control.lost",
            "storm-control (multiple interfaces)",
            "ESR does not support storm-control — L2 feature",
            Some("Handle storm protection on upstream L2 switch"),
        );
    }

    // STP
    if has_stp {
        out.push("!".to_string());
        out.push("! LOST CONTROL: STP/spanning-tree settings not migrated.".to_string());
        out.push("!   ESR does not participate in L2 STP.".to_string());
        out.push("!   Ensure loop prevention is handled by upstream switch.".to_string());
        report.add_manual(
            "stp.lost",
            "spanning-tree (global)",
            "ESR does not support STP — L2 feature",
            Some("Handle STP on upstream L2 switch (Eltex MES)"),
        );
    }

    // Voice VLAN
    if has_voice_vlan {
        out.push("!".to_string());
        out.push("! LOST FEATURE: voice VLAN settings not migrated.".to_string());
        out.push("!   ESR does not support voice VLAN (L2 feature).".to_string());
        out.push("!   Configure voice VLAN on upstream switch with DHCP option 150/66.".to_string());
        report.add_manual(
            "voice_vlan.lost",
            "switchport voice vlan (multiple interfaces)",
            "Voice VLAN not supported on ESR — L2 feature",
            Some("Configure voice VLAN on Eltex MES switch"),
        );
    }

    out.push("! ============================================================".to_string());
    out.push(String::new());
}

fn render_hsrp_as_vrrp(hsrp: &HsrpGroup, out: &mut Vec<String>, report: &mut ConversionReport) {
    out.push(format!(" vrrp {} ip {}", hsrp.group_id, hsrp.virtual_ip));
    report.add_approximate(
        "hsrp_to_vrrp",
        &format!("standby {} ip {}", hsrp.group_id, hsrp.virtual_ip),
        &format!("vrrp {} ip {}", hsrp.group_id, hsrp.virtual_ip),
        "HSRP → VRRP: wire-incompatible. MAC: 0000.0c07.acXX → 0000.5e00.01XX. \
         Migrate all nodes simultaneously.",
    );
    if let Some(priority) = hsrp.priority {
        out.push(format!(" vrrp {} priority {}", hsrp.group_id, priority));
    }
    if hsrp.preempt {
        out.push(format!(" vrrp {} preempt", hsrp.group_id));
    }
    if !hsrp.track.is_empty() {
        out.push(format!(" ! MANUAL: HSRP track not supported in ESR VRRP"));
        report.add_manual("hsrp.track",
            &format!("standby {} track", hsrp.group_id),
            "HSRP object tracking not supported in ESR VRRP", None);
    }
}

// ---------------------------------------------------------------------------
// Interface naming helpers
// ---------------------------------------------------------------------------

pub fn ios_to_esr_ifname_with_offset(iface: &Interface, fe_count: u32) -> String {
    match &iface.name.kind {
        InterfaceKind::FastEthernet => {
            let port = extract_last_port_number(&iface.name.id).unwrap_or(1);
            format!("gigabitethernet 1/0/{}", port)
        }
        InterfaceKind::GigabitEthernet => {
            let port = extract_last_port_number(&iface.name.id).unwrap_or(1);
            if fe_count > 0 {
                // Смещаем GE после FE чтобы не конфликтовать
                format!("gigabitethernet 1/0/{}  ! was {}", fe_count + port, iface.name.original)
            } else {
                format!("gigabitethernet 1/0/{}", port)
            }
        }
        InterfaceKind::TenGigabitEthernet => {
            let port = extract_last_port_number(&iface.name.id).unwrap_or(1);
            format!("tengigabitethernet 1/0/{}", port)
        }
        InterfaceKind::Loopback => {
            let num: u32 = iface.name.id.parse().unwrap_or(0);
            format!("loopback {}", num + 1)
        }
        InterfaceKind::Vlan => format!("vlan {}", iface.name.id),
        InterfaceKind::Tunnel => format!("tunnel {}", iface.name.id),
        _ => iface.name.original.to_lowercase(),
    }
}

// Для обратной совместимости с renderer.rs
pub fn ios_to_esr_ifname(name: &InterfaceName) -> String {
    match &name.kind {
        InterfaceKind::FastEthernet | InterfaceKind::GigabitEthernet => {
            let port = name.id.split('/').last()
                .and_then(|s| s.parse::<u32>().ok()).unwrap_or(1);
            format!("gigabitethernet 1/0/{}", port)
        }
        InterfaceKind::TenGigabitEthernet => {
            let port = name.id.split('/').last()
                .and_then(|s| s.parse::<u32>().ok()).unwrap_or(1);
            format!("tengigabitethernet 1/0/{}", port)
        }
        InterfaceKind::Loopback => {
            let num: u32 = name.id.parse().unwrap_or(0);
            format!("loopback {}", num + 1)
        }
        InterfaceKind::Vlan => format!("vlan {}", name.id),
        InterfaceKind::Tunnel => format!("tunnel {}", name.id),
        _ => name.original.to_lowercase(),
    }
}

fn extract_last_port_number(id: &str) -> Option<u32> {
    id.split('/').last()?.parse().ok()
}

pub fn ospf_area_str(area: &OspfArea) -> String {
    match area {
        OspfArea::Backbone    => "0.0.0.0".to_string(),
        OspfArea::Normal(n)   => {
            let b3 = (n >> 8) as u8;
            let b4 = (n & 0xff) as u8;
            format!("0.0.{}.{}", b3, b4)
        }
        OspfArea::IpFormat(ip) => ip.to_string(),
    }
}
