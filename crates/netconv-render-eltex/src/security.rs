use netconv_core::ir::*;
use netconv_core::report::ConversionReport;

/// Security zones — ключевое отличие ESR от Cisco IOS.
/// На ESR каждый интерфейс ОБЯЗАТЕЛЬНО привязывается к зоне.
/// Без зоны трафик не проходит.
///
/// Стратегия: определяем зоны эвристически по типу интерфейса и NAT:
/// - NAT outside → zone "WAN" (Untrusted)
/// - NAT inside, OSPF, helper-address → zone "LAN" (Trusted)
/// - Loopback → zone "LAN"
/// - Остальные → zone "LAN" с предупреждением
pub fn render_security_zones(cfg: &NetworkConfig, out: &mut Vec<String>, report: &mut ConversionReport) {
    // Определяем какие зоны нужны
    let has_wan = cfg.interfaces.iter().any(|i| i.nat_direction == Some(NatDirection::Outside));
    let has_lan = cfg.interfaces.iter().any(|i|
        i.nat_direction == Some(NatDirection::Inside) ||
        i.nat_direction.is_none()
    );

    out.push("!".to_string());
    out.push("! Security zones".to_string());

    // Объявляем зоны
    if has_lan {
        out.push("security zone LAN".to_string());
        out.push(" exit".to_string());
    }
    if has_wan {
        out.push("security zone WAN".to_string());
        out.push(" exit".to_string());
    }

    out.push(String::new());

    // Firewall правила между зонами
    if has_wan && has_lan {
        render_basic_firewall(out, report);
    }

    report.add_approximate(
        "security_zones",
        "# (implicit: Cisco IOS has no mandatory security zones)",
        "security zone LAN / security zone WAN",
        "ESR требует security zones на всех интерфейсах. \
         LAN/WAN определены эвристически по NAT направлению. \
         Проверь зоны и firewall правила перед применением.",
    );
}

fn render_basic_firewall(out: &mut Vec<String>, report: &mut ConversionReport) {
    // Минимальные firewall правила для работы:
    // LAN → WAN: разрешить исходящий
    // WAN → self: разрешить SSH/ICMP для управления
    out.push("!".to_string());
    out.push("! Basic firewall rules (auto-generated — review carefully)".to_string());

    // LAN → WAN
    out.push("security zone-pair LAN WAN".to_string());
    out.push(" rule 10".to_string());
    out.push("  action permit".to_string());
    out.push("  enable".to_string());
    out.push("  exit".to_string());
    out.push(" exit".to_string());

    // WAN → self (управление)
    out.push("security zone-pair WAN self".to_string());
    out.push(" rule 10".to_string());
    out.push("  action permit".to_string());
    out.push("  match protocol tcp".to_string());
    out.push("  match destination-port 22".to_string());
    out.push("  enable".to_string());
    out.push("  exit".to_string());
    out.push(" rule 20".to_string());
    out.push("  action permit".to_string());
    out.push("  match protocol icmp".to_string());
    out.push("  enable".to_string());
    out.push("  exit".to_string());
    out.push(" exit".to_string());

    // LAN → self (управление из LAN)
    out.push("security zone-pair LAN self".to_string());
    out.push(" rule 10".to_string());
    out.push("  action permit".to_string());
    out.push("  enable".to_string());
    out.push("  exit".to_string());
    out.push(" exit".to_string());

    out.push(String::new());

    report.add_approximate(
        "firewall",
        "# (implicit: Cisco IOS firewall rules not migrated)",
        "security zone-pair LAN WAN / WAN self / LAN self",
        "Базовые firewall правила: LAN→WAN permit all, WAN→self permit SSH+ICMP, LAN→self permit all. \
         Настрой более строгие правила согласно security policy.",
    );
}
