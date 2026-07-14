use netconv_core::ir::*;
use netconv_core::report::ConversionReport;

/// Рендер интерфейсов для Eltex MES (L2/switch-профиль).
///
/// Намеренно отдельный файл от `crate::iface` — тот написан под ESR
/// (router/firewall: security zones, ip nat, zone-aware ACL) и делает
/// принципиально другие вещи с тем же самым `interface <name>` в IR.
/// Смешивать их в одной функции — ровно та ошибка, от которой уходит
/// весь этот рефакторинг.
pub fn render_interfaces(
    cfg: &NetworkConfig,
    out: &mut Vec<String>,
    report: &mut ConversionReport,
) {
    for iface in &cfg.interfaces {
        render_interface(iface, out, report);
    }
}

fn render_interface(iface: &Interface, out: &mut Vec<String>, report: &mut ConversionReport) {
    let mes_name = ios_to_mes_ifname(&iface.name);
    let src_block = format!("interface {}", iface.name.original);

    out.push("!".to_string());
    out.push(format!("interface {}", mes_name));

    if let Some(desc) = &iface.description {
        out.push(format!(" description {}", desc));
        report.add_exact(
            "interface.description",
            &src_block,
            &format!("description {}", desc),
        );
    }

    if iface.shutdown {
        out.push(" shutdown".to_string());
        report.add_exact("interface.shutdown", &src_block, "shutdown");
    } else {
        out.push(" no shutdown".to_string());
        report.add_exact("interface.shutdown", &src_block, "no shutdown");
    }

    if let Some(mtu) = iface.mtu {
        out.push(format!(" mtu {}", mtu));
        report.add_exact("interface.mtu", &src_block, &format!("mtu {}", mtu));
    }

    if let Some(speed) = &iface.speed {
        match speed {
            InterfaceSpeed::Auto => {
                out.push(" speed auto".to_string());
                report.add_exact("interface.speed", &src_block, "speed auto");
            }
            InterfaceSpeed::Mbps(mbps) => {
                out.push(format!(" speed {}", mbps));
                report.add_exact("interface.speed", &src_block, &format!("speed {}", mbps));
            }
        }
    }

    if let Some(duplex) = &iface.duplex {
        let d = match duplex {
            Duplex::Full => "full",
            Duplex::Half => "half",
            Duplex::Auto => "auto",
        };
        out.push(format!(" duplex {}", d));
        report.add_exact("interface.duplex", &src_block, &format!("duplex {}", d));
    }

    // IP-адресация (в основном для management SVI — `interface vlan N`).
    // На физическом switchport-порту MES адрес одновременно со
    // switchport не применяется — как и на Cisco.
    for (i, addr) in iface.addresses.iter().enumerate() {
        if i == 0 && !addr.secondary {
            out.push(format!(" ip address {}", addr.prefix));
            report.add_exact(
                "interface.ip",
                &format!("ip address {} ({})", addr.prefix, iface.name.original),
                &format!("ip address {}", addr.prefix),
            );
        } else {
            out.push(format!(" ip address {} secondary", addr.prefix));
            report.add_approximate(
                "interface.ip.secondary",
                &format!("ip address {} secondary", addr.prefix),
                &format!("ip address {} secondary", addr.prefix),
                "Проверь поддержку secondary-адресов на конкретной модели MES",
            );
        }
    }

    // switchport
    if let Some(l2) = &iface.l2 {
        render_l2(l2, out, report, &src_block);
    }

    // Voice VLAN
    if let Some(vv) = iface.voice_vlan {
        out.push(format!(" switchport voice vlan {}", vv));
        report.add_approximate(
            "interface.voice_vlan",
            &format!("switchport voice vlan {}", vv),
            &format!("switchport voice vlan {}", vv),
            "Команда подтверждена для MES1024/1124/2124/3100. На MES23xx/33xx/53xx voice VLAN обычно настраивается через LLDP-MED политику (switchport mode general + lldp med network-policy), эта команда может не сработать напрямую — проверь по мануалу конкретной модели.",
        );
    }

    // Storm control — у MES та же шкала level, что и у Cisco (в отличие
    // от VRP, где нужен пересчёт в percent) — перенос почти буквальный.
    if let Some(sc) = &iface.storm_control {
        if let Some(level) = sc.broadcast_level {
            out.push(format!(" storm-control broadcast level {}", level));
            report.add_approximate(
                "interface.storm_control",
                &format!("storm-control broadcast level {}", level),
                &format!("storm-control broadcast level {}", level),
                "MES использует ту же шкалу level, что и Cisco — проверь единицы измерения на конкретной модели",
            );
        }
        if let Some(level) = sc.multicast_level {
            out.push(format!(" storm-control multicast level {}", level));
            report.add_approximate(
                "interface.storm_control",
                &format!("storm-control multicast level {}", level),
                &format!("storm-control multicast level {}", level),
                "MES использует ту же шкалу level, что и Cisco",
            );
        }
        if let Some(level) = sc.unicast_level {
            out.push(format!(" storm-control unicast level {}", level));
            report.add_approximate(
                "interface.storm_control",
                &format!("storm-control unicast level {}", level),
                &format!("storm-control unicast level {}", level),
                "MES использует ту же шкалу level, что и Cisco",
            );
        }
    }

    // STP per-interface
    if iface.stp.portfast {
        // Подтверждено дословно: MES2324(config-if)# spanning-tree portfast
        out.push(" spanning-tree portfast".to_string());
        report.add_exact("stp.portfast", &src_block, "spanning-tree portfast");
    }

    if iface.stp.bpduguard {
        // Подтверждено дословно: MES2324(config-if)# spanning-tree bpduguard enable
        out.push(" spanning-tree bpduguard enable".to_string());
        report.add_exact(
            "stp.bpduguard",
            &src_block,
            "spanning-tree bpduguard enable",
        );
    }

    if iface.stp.bpdufilter {
        let is_trunk = iface
            .l2
            .as_ref()
            .map(|l| l.mode == L2Mode::Trunk)
            .unwrap_or(false);
        if is_trunk {
            out.push(" ! ⚠ RISK: bpdu filtering NOT applied — trunk port detected.".to_string());
            out.push(" !   Applying it on trunk/uplink ports can cause STP loops.".to_string());
            out.push(
                " !   Original config had 'spanning-tree bpdufilter enable' — review manually."
                    .to_string(),
            );
            report.add_manual(
                "stp.bpdufilter",
                "spanning-tree bpdufilter enable (on trunk port)",
                "RISK: trunk port detected — bpdu filtering NOT auto-applied.",
                Some("Review port role. Apply 'spanning-tree bpdu filtering' only if this is truly an edge port."),
            );
        } else {
            // Важно: команда называется иначе, чем на Cisco/VRP —
            // "bpdu filtering", не "bpdufilter enable".
            out.push(" spanning-tree bpdu filtering".to_string());
            report.add_approximate(
                "stp.bpdufilter",
                "spanning-tree bpdufilter enable",
                "spanning-tree bpdu filtering",
                "MES: команда называется 'spanning-tree bpdu filtering' (не 'bpdufilter enable', как на Cisco/VRP)",
            );
        }
    }

    if iface.stp.guard_root {
        out.push(" spanning-tree guard root".to_string());
        report.add_approximate(
            "stp.guard_root",
            &src_block,
            "spanning-tree guard root",
            "Проверь точное имя команды root guard на конкретной модели MES",
        );
    }

    out.push(String::new());
}

fn render_l2(l2: &L2Config, out: &mut Vec<String>, report: &mut ConversionReport, ctx: &str) {
    match l2.mode {
        L2Mode::Access => {
            // Подтверждено дословно: switchport mode access / switchport access vlan N
            out.push(" switchport mode access".to_string());
            report.add_exact("interface.l2", ctx, "switchport mode access");
            if let Some(vlan) = l2.access_vlan {
                out.push(format!(" switchport access vlan {}", vlan));
                report.add_exact(
                    "interface.l2.vlan",
                    &format!("switchport access vlan {}", vlan),
                    &format!("switchport access vlan {}", vlan),
                );
            }
        }
        L2Mode::Trunk => {
            // Подтверждено дословно: switchport mode trunk
            out.push(" switchport mode trunk".to_string());
            report.add_exact("interface.l2", ctx, "switchport mode trunk");

            if let Some(native) = l2.trunk_native {
                out.push(format!(" switchport trunk native vlan {}", native));
                report.add_exact(
                    "interface.l2.native",
                    &format!("switchport trunk native vlan {}", native),
                    &format!("switchport trunk native vlan {}", native),
                );
            }

            if let Some(allowed) = &l2.trunk_allowed {
                let vlan_list = allowed
                    .iter()
                    .map(|v| v.to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                out.push(format!(" switchport trunk allowed vlan add {}", vlan_list));
                report.add_approximate(
                    "interface.l2.trunk_allowed",
                    "switchport trunk allowed vlan ...",
                    &format!("switchport trunk allowed vlan add {}", vlan_list),
                    "MES добавляет VLAN'ы инкрементально ('add'), а не заменяет список целиком, как Cisco/VRP — на чистом порту эквивалентно, но на уже настроенном порту проверь текущий список перед применением",
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Cisco IOS имя → Eltex MES имя. MES14xx/24xx используют ту же
/// 2-уровневую нумерацию портов, что и Cisco (подтверждено документацией
/// Eltex: "interface gigabitethernet 0/1") — поэтому номер порта не
/// пересчитывается, меняется только разделитель. Для MES23xx/33xx/53xx
/// (3-уровневая нумерация unit/slot/port) исходный номер может не
/// совпадать с портом на целевом свитче — это фиксируется как
/// Approximate на каждом интерфейсе через report в render_interface.
pub fn ios_to_mes_ifname(name: &InterfaceName) -> String {
    match &name.kind {
        InterfaceKind::GigabitEthernet => format!("GigabitEthernet {}", name.id),
        InterfaceKind::TenGigabitEthernet => format!("TengigabitEthernet {}", name.id),
        InterfaceKind::FastEthernet => format!("FastEthernet {}", name.id),
        InterfaceKind::Vlan => format!("vlan {}", name.id),
        InterfaceKind::Loopback => format!("loopback {}", name.id),
        _ => name.original.clone(),
    }
}
