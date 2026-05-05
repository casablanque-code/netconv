use netconv_core::ir::*;
use netconv_core::report::ConversionReport;

pub fn render_vlans(cfg: &NetworkConfig, out: &mut Vec<String>, report: &mut ConversionReport) {
    // Собираем VLAN из двух источников:
    // 1. Явно объявленные vlan блоки
    // 2. VLAN упомянутые в интерфейсах (access vlan, trunk allowed, voice vlan)
    let mut all_vlans: std::collections::BTreeMap<u16, Option<String>> = std::collections::BTreeMap::new();

    // Из явных vlan блоков
    for vlan in &cfg.vlans {
        all_vlans.insert(vlan.id, vlan.name.clone());
    }

    // Из интерфейсов — добавляем если ещё не объявлены
    for iface in &cfg.interfaces {
        if let Some(l2) = &iface.l2 {
            if let Some(vid) = l2.access_vlan {
                all_vlans.entry(vid).or_insert(None);
            }
            if let Some(allowed) = &l2.trunk_allowed {
                for vid in allowed {
                    all_vlans.entry(*vid).or_insert(None);
                }
            }
        }
        if let Some(vv) = iface.voice_vlan {
            all_vlans.entry(vv).or_insert(None);
        }
    }

    // VLAN 1 — существует по умолчанию, не нужно объявлять
    all_vlans.remove(&1);

    if all_vlans.is_empty() { return; }

    out.push("#".to_string());

    // vlan batch — создаём все VLAN одной командой
    let vlan_ids: Vec<String> = all_vlans.keys().map(|v| v.to_string()).collect();
    let batch_cmd = format!("vlan batch {}", vlan_ids.join(" "));
    out.push(batch_cmd.clone());
    report.add_approximate(
        "vlan.batch",
        "vlan <id> (multiple blocks)",
        &batch_cmd,
        "VRP: 'vlan batch' создаёт несколько VLAN одной командой",
    );

    // Отдельные блоки только для VLAN с именами
    for (id, name) in &all_vlans {
        if let Some(n) = name {
            out.push("#".to_string());
            out.push(format!("vlan {}", id));
            // Cisco: vlan X / name FOO
            // VRP:   vlan X / description FOO
            out.push(format!(" description {}", n));
            report.add_approximate(
                "vlan.name",
                &format!("vlan {} / name {}", id, n),
                &format!("vlan {} / description {}", id, n),
                "VRP: description вместо name для VLAN",
            );
        }
    }

    out.push(String::new());
}
