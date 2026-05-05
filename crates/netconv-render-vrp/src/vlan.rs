use netconv_core::ir::*;
use netconv_core::report::ConversionReport;

pub fn render_vlans(cfg: &NetworkConfig, out: &mut Vec<String>, report: &mut ConversionReport) {
    let mut all_vlans: std::collections::BTreeMap<u16, Option<String>> = std::collections::BTreeMap::new();

    // Собираем из явных vlan блоков
    for vlan in &cfg.vlans {
        all_vlans.insert(vlan.id, vlan.name.clone());
    }

    // Собираем из интерфейсов
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

    all_vlans.remove(&1); // VLAN 1 существует по умолчанию

    if all_vlans.is_empty() { return; }

    // Разделяем на voice и data VLAN для MSTP heuristic
    let voice_vlans: Vec<u16> = cfg.interfaces.iter()
        .filter_map(|i| i.voice_vlan)
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter().collect();

    let data_vlans: Vec<u16> = all_vlans.keys()
        .filter(|v| !voice_vlans.contains(v))
        .copied().collect();

    out.push("#".to_string());

    // vlan batch
    let vlan_ids: Vec<String> = all_vlans.keys().map(|v| v.to_string()).collect();
    let batch_cmd = format!("vlan batch {}", vlan_ids.join(" "));
    out.push(batch_cmd.clone());
    report.add_approximate(
        "vlan.batch",
        "vlan <id> (multiple blocks)",
        &batch_cmd,
        "VRP: 'vlan batch' создаёт несколько VLAN одной командой",
    );

    // Блоки с description для именованных VLAN
    for (id, name) in &all_vlans {
        match name {
            Some(n) => {
                out.push("#".to_string());
                out.push(format!("vlan {}", id));
                out.push(format!(" description {}", n));
                report.add_approximate(
                    "vlan.name",
                    &format!("vlan {} / name {}", id, n),
                    &format!("vlan {} / description {}", id, n),
                    "VRP: description вместо name для VLAN",
                );
            }
            None => {
                // VLAN без имени — только если это voice VLAN, добавляем INFO
                if voice_vlans.contains(id) {
                    out.push("#".to_string());
                    out.push(format!("vlan {}", id));
                    out.push(format!(" # INFO: VLAN {} used as voice VLAN (no name in source config)", id));
                }
            }
        }
    }

    out.push(String::new());

    // MSTP heuristic — генерим starting point если есть STP с PVST
    render_mstp_suggestion(cfg, &data_vlans, &voice_vlans, out, report);
}

/// Генерит закомментированный MSTP starting point на основе реальных VLAN из конфига.
/// Data VLAN → instance 1, Voice VLAN → instance 2.
/// Это эвристика — пользователь должен проверить и скорректировать.
fn render_mstp_suggestion(
    cfg: &NetworkConfig,
    data_vlans: &[u16],
    voice_vlans: &[u16],
    out: &mut Vec<String>,
    report: &mut ConversionReport,
) {
    let is_pvst = cfg.stp.as_ref()
        .map(|s| matches!(s.mode, StpMode::RapidPvst | StpMode::Pvst))
        .unwrap_or(false);

    if !is_pvst || (data_vlans.is_empty() && voice_vlans.is_empty()) { return; }

    let data_str = data_vlans.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(" ");
    let voice_str = voice_vlans.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(" ");

    out.push("#".to_string());
    out.push("# ── MSTP STARTING POINT (auto-generated heuristic) ─────────────".to_string());
    out.push("# Cisco rapid-pvst detected. MSTP preserves per-VLAN topology.".to_string());
    out.push("# Review instance assignments before applying.".to_string());
    out.push("# Replace 'stp mode rstp' above with:".to_string());
    out.push("#".to_string());
    out.push("# stp mode mstp".to_string());
    out.push("# stp region-configuration".to_string());
    out.push("#  region-name MIGRATED_REGION".to_string());
    out.push("#  revision-level 1".to_string());
    if !data_vlans.is_empty() {
        out.push(format!("#  instance 1 vlan {}   # data VLANs", data_str));
    }
    if !voice_vlans.is_empty() {
        out.push(format!("#  instance 2 vlan {}   # voice VLANs", voice_str));
    }
    out.push("#  active region-configuration".to_string());
    out.push("# ────────────────────────────────────────────────────────────────".to_string());
    out.push(String::new());

    report.add_approximate(
        "stp.mstp_suggestion",
        "spanning-tree vlan ... (multiple)",
        "# MSTP starting point (see comments)",
        &format!(
            "Auto-generated MSTP config: instance 1 = data VLANs [{}],              instance 2 = voice VLANs [{}].              Review before applying — this is a heuristic.",
            data_str, voice_str
        ),
    );
}
