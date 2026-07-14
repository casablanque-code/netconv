use netconv_core::ir::*;
use netconv_core::report::ConversionReport;

/// VLAN database для Eltex MES. Синтаксис подтверждён документацией
/// MES23xx/33xx/53xx (Eltex, "Initial setup of Ethernet switches"):
///
///   vlan database
///    vlan <id> name <name>
///   exit
///
/// Другие семейства MES (14xx/24xx) входят в VLAN иначе (`vlan <id>`
/// в глобальном режиме, затем `vlan active` и `name <name>`, без
/// `vlan database`). netconv не знает точную модель целевого свитча,
/// поэтому каждая VLAN помечена Approximate с пояснением, а не Exact —
/// это тот самый случай, когда синтаксис реален и документирован, но
/// варьируется между семействами одного вендора.
pub fn render_vlans(cfg: &NetworkConfig, out: &mut Vec<String>, report: &mut ConversionReport) {
    if cfg.vlans.is_empty() {
        return;
    }

    out.push("!".to_string());
    out.push("vlan database".to_string());

    for vlan in &cfg.vlans {
        match &vlan.name {
            Some(name) => {
                out.push(format!(" vlan {} name {}", vlan.id, name));
                report.add_approximate(
                    "vlan",
                    &format!("vlan {} / name {}", vlan.id, name),
                    &format!("vlan {} name {}", vlan.id, name),
                    "Синтаксис подтверждён для MES23xx/33xx/53xx. На MES14xx/24xx вход в VLAN отличается (vlan <id> без 'vlan database', затем 'vlan active') — проверь по мануалу конкретной модели.",
                );
            }
            None => {
                out.push(format!(" vlan {}", vlan.id));
                report.add_approximate(
                    "vlan",
                    &format!("vlan {}", vlan.id),
                    &format!("vlan {}", vlan.id),
                    "Синтаксис подтверждён для MES23xx/33xx/53xx — для других семейств MES проверь вход в VLAN по мануалу.",
                );
            }
        }
    }

    out.push("exit".to_string());
    out.push(String::new());
}
