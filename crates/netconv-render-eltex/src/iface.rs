use netconv_core::ir::*;
use netconv_core::report::ConversionReport;

pub fn render_interfaces(cfg: &NetworkConfig, out: &mut Vec<String>, report: &mut ConversionReport) {
    for iface in &cfg.interfaces {
        render_interface(iface, out, report);
    }
}

fn render_interface(iface: &Interface, out: &mut Vec<String>, report: &mut ConversionReport) {
    let esr_name = ios_to_esr_ifname(&iface.name);
    let src_block = format!("interface {}", iface.name.original);

    out.push("!".to_string());
    out.push(format!("interface {}", esr_name));

    if let Some(desc) = &iface.description {
        out.push(format!(" description {}", desc));
        report.add_exact("interface.description", &src_block, &format!("description {}", desc));
    }

    // Security zone — определяем по NAT направлению
    let zone = match &iface.nat_direction {
        Some(NatDirection::Outside) => "WAN",
        _ => match &iface.name.kind {
            InterfaceKind::Loopback => "LAN",
            _ => "LAN",
        }
    };
    out.push(format!(" security-zone {}", zone));
    report.add_approximate(
        "interface.security_zone",
        &format!("# (no zone in Cisco IOS for {})", iface.name.original),
        &format!("security-zone {}", zone),
        "ESR: security-zone обязательна. Определена эвристически по NAT/типу интерфейса.",
    );

    // IP addresses
    for (i, addr) in iface.addresses.iter().enumerate() {
        // ESR использует CIDR нотацию: ip address 192.168.1.1/24
        if i == 0 && !addr.secondary {
            out.push(format!(" ip address {}", addr.prefix));
            report.add_exact(
                "interface.ip",
                &format!("ip address {} ({})", addr.prefix, iface.name.original),
                &format!("ip address {}", addr.prefix),
            );
        } else {
            // ESR поддерживает несколько адресов на интерфейсе
            out.push(format!(" ip address {}", addr.prefix));
            report.add_approximate(
                "interface.ip.secondary",
                &format!("ip address {} secondary", addr.prefix),
                &format!("ip address {}", addr.prefix),
                "ESR: несколько ip address на интерфейсе без ключевого слова secondary",
            );
        }
    }

    // Shutdown
    if iface.shutdown {
        out.push(" shutdown".to_string());
        report.add_exact("interface.shutdown", &src_block, "shutdown");
    }
    // ESR: нет "no shutdown" — интерфейс активен по умолчанию

    // MTU
    if let Some(mtu) = iface.mtu {
        out.push(format!(" mtu {}", mtu));
        report.add_exact("interface.mtu", &src_block, &format!("mtu {}", mtu));
    }

    // Helper address → DHCP relay
    for helper in &iface.helper_addresses {
        out.push(format!(" ip helper-address {}", helper));
        report.add_approximate(
            "interface.helper",
            &format!("ip helper-address {}", helper),
            &format!("ip helper-address {}", helper),
            "ESR: ip helper-address синтаксис совпадает с Cisco",
        );
    }

    // ACL in/out
    if let Some(acl_in) = &iface.acl_in {
        // ESR: ip access-group <name> in  (аналогично Cisco)
        out.push(format!(" ip access-group {} in", acl_in));
        report.add_approximate(
            "interface.acl",
            &format!("ip access-group {} in", acl_in),
            &format!("ip access-group {} in", acl_in),
            "ESR: ip access-group синтаксис совпадает, но ACL нужно объявить отдельно",
        );
    }
    if let Some(acl_out) = &iface.acl_out {
        out.push(format!(" ip access-group {} out", acl_out));
        report.add_approximate(
            "interface.acl",
            &format!("ip access-group {} out", acl_out),
            &format!("ip access-group {} out", acl_out),
            "ESR: ip access-group синтаксис совпадает",
        );
    }

    // OSPF на интерфейсе
    if let Some(ospf) = &iface.ospf {
        let area_str = ospf_area_str(&ospf.area);
        out.push(format!(" ip ospf instance {}", ospf.process_id));
        out.push(format!(" ip ospf area {}", area_str));
        out.push(" ip ospf".to_string());
        report.add_approximate(
            "ospf.interface",
            &format!("ip ospf {} area {} (on {})", ospf.process_id, area_str, iface.name.original),
            &format!("ip ospf instance {} / ip ospf area {} / ip ospf", ospf.process_id, area_str),
            "ESR: OSPF на интерфейсе через ip ospf instance + ip ospf area + ip ospf (enable)",
        );

        if let Some(cost) = ospf.cost {
            out.push(format!(" ip ospf cost {}", cost));
            report.add_exact("ospf.cost", &src_block, &format!("ip ospf cost {}", cost));
        }
    }

    // HSRP → VRRP (ESR поддерживает VRRP)
    for hsrp in &iface.hsrp {
        render_hsrp_as_vrrp(hsrp, &esr_name, out, report);
    }

    // NAT — помечаем, сам NAT рендерится отдельно
    if iface.nat_direction.is_some() {
        out.push(format!(" ! nat: {} (NAT configured separately)", 
            if iface.nat_direction == Some(NatDirection::Inside) { "inside" } else { "outside" }));
    }

    out.push(" exit".to_string());
    out.push(String::new());
}

fn render_hsrp_as_vrrp(
    hsrp: &HsrpGroup,
    _iface_name: &str,
    out: &mut Vec<String>,
    report: &mut ConversionReport,
) {
    // ESR VRRP синтаксис:
    // vrrp <group> ip <vip>
    // vrrp <group> priority <n>
    // vrrp <group> preempt
    out.push(format!(" vrrp {} ip {}", hsrp.group_id, hsrp.virtual_ip));

    report.add_approximate(
        "hsrp_to_vrrp",
        &format!("standby {} ip {}", hsrp.group_id, hsrp.virtual_ip),
        &format!("vrrp {} ip {}", hsrp.group_id, hsrp.virtual_ip),
        "HSRP → VRRP: протоколы бинарно несовместимы. MAC: 0000.0c07.acXX → 0000.5e00.01XX. \
         Переводи все узлы одновременно.",
    );

    if let Some(priority) = hsrp.priority {
        out.push(format!(" vrrp {} priority {}", hsrp.group_id, priority));
    }

    if hsrp.preempt {
        out.push(format!(" vrrp {} preempt", hsrp.group_id));
    }

    if !hsrp.track.is_empty() {
        out.push(format!(" ! MANUAL: HSRP track not directly supported in ESR VRRP"));
        report.add_manual(
            "hsrp.track",
            &format!("standby {} track ...", hsrp.group_id),
            "HSRP object tracking not supported in ESR VRRP",
            None,
        );
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Cisco IOS имя → Eltex ESR имя
///
/// ESR нумерация: gigabitethernet 1/0/N где N — глобальный номер порта.
/// FastEthernet и GigabitEthernet маппятся последовательно:
///   FastEthernet0/1..0/24  → gigabitethernet 1/0/1..1/0/24
///   GigabitEthernet0/1..0/2 → gigabitethernet 1/0/25..1/0/26 (после FE портов)
///
/// Это эвристика — реальная нумерация зависит от модели ESR.
/// Проверь соответствие портов перед применением.
pub fn ios_to_esr_ifname(name: &InterfaceName) -> String {
    match &name.kind {
        InterfaceKind::FastEthernet => {
            // FastEthernet0/N → gigabitethernet 1/0/N
            let port_num = extract_last_port_number(&name.id).unwrap_or(1);
            format!("gigabitethernet 1/0/{}", port_num)
        }
        InterfaceKind::GigabitEthernet => {
            // GigabitEthernet0/N → gigabitethernet 1/0/(24+N) чтобы не конфликтовать с FE
            // Если нет FastEthernet в конфиге — будет gigabitethernet 1/0/N
            let port_num = extract_last_port_number(&name.id).unwrap_or(1);
            // Используем оригинальное имя как комментарий
            format!("gigabitethernet 1/0/{} ! was {}", port_num, name.original)
        }
        InterfaceKind::TenGigabitEthernet => {
            let port_num = extract_last_port_number(&name.id).unwrap_or(1);
            format!("tengigabitethernet 1/0/{}", port_num)
        }
        InterfaceKind::Loopback => {
            let num: u32 = name.id.parse().unwrap_or(0);
            // ESR loopback нумерация начинается с 1
            format!("loopback {}", num + 1)
        }
        InterfaceKind::Vlan => {
            format!("vlan {}", name.id)
        }
        InterfaceKind::Tunnel => {
            format!("tunnel {}", name.id)
        }
        _ => name.original.to_lowercase(),
    }
}

fn extract_last_port_number(id: &str) -> Option<u32> {
    id.split('/').last()?.parse().ok()
}

pub fn ospf_area_str(area: &OspfArea) -> String {
    match area {
        OspfArea::Backbone => "0.0.0.0".to_string(),
        OspfArea::Normal(n) => {
            // ESR поддерживает оба формата, используем IP формат
            let b3 = (n >> 8) as u8;
            let b4 = (n & 0xff) as u8;
            format!("0.0.{}.{}", b3, b4)
        }
        OspfArea::IpFormat(ip) => ip.to_string(),
    }
}
