use serde::{Deserialize, Serialize};

use crate::ir::NetworkConfig;

// ---------------------------------------------------------------------------
// DeviceProfile — явный выбор класса устройства
// ---------------------------------------------------------------------------
//
// Профиль отражает реальную роль железа, а не синтаксис вендора: коммутатор
// не становится маршрутизатором оттого, что его конфиг успешно распарсился.
// Профиль всегда выбирается пользователем явно (вкладка в UI, --profile в
// CLI) — конвертер намеренно не пытается угадать его эвристикой по
// содержимому конфига, чтобы не подменять решение пользователя догадкой.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceProfile {
    /// L2: коммутатор — VLAN, access/trunk, STP, port-security, voice VLAN
    L2Switch,
    /// L3: маршрутизатор/firewall — routing, ACL, NAT, HSRP/VRRP
    L3Router,
}

impl DeviceProfile {
    pub fn label(&self) -> &'static str {
        match self {
            DeviceProfile::L2Switch => "L2 (switching)",
            DeviceProfile::L3Router => "L3 (routing)",
        }
    }
}

// ---------------------------------------------------------------------------
// DomainMismatch — найденная в IR сущность чужого домена
// ---------------------------------------------------------------------------
//
// Рендереры пока не фильтруют IR по профилю (это следующий шаг), поэтому
// на данном этапе detect_domain_mismatches только формирует список того,
// что обнаружено не по адресу — вместо того, чтобы рендерер молча дропал
// это с комментарием в самом выходном конфиге, как раньше делал
// EltexRenderer для L2-команд.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainMismatch {
    /// Короткий идентификатор домена/фичи, например "L3/ospf"
    pub domain: String,
    pub detail: String,
}

/// Сверяет NetworkConfig с выбранным профилем и возвращает список
/// найденных сущностей чужого домена. IR не изменяется.
pub fn detect_domain_mismatches(config: &NetworkConfig, profile: DeviceProfile) -> Vec<DomainMismatch> {
    let mut out = Vec::new();

    match profile {
        DeviceProfile::L2Switch => {
            if !config.routing.static_routes.is_empty() {
                out.push(DomainMismatch {
                    domain: "L3/static".to_string(),
                    detail: format!(
                        "{} статических маршрутов — не относится к L2-профилю",
                        config.routing.static_routes.len()
                    ),
                });
            }
            if !config.routing.ospf.is_empty() {
                out.push(DomainMismatch {
                    domain: "L3/ospf".to_string(),
                    detail: format!("{} процессов OSPF", config.routing.ospf.len()),
                });
            }
            if config.routing.bgp.is_some() {
                out.push(DomainMismatch {
                    domain: "L3/bgp".to_string(),
                    detail: "конфигурация BGP".to_string(),
                });
            }
            if !config.routing.eigrp.is_empty() {
                out.push(DomainMismatch {
                    domain: "L3/eigrp".to_string(),
                    detail: format!("{} процессов EIGRP", config.routing.eigrp.len()),
                });
            }
            if !config.acls.is_empty() {
                out.push(DomainMismatch {
                    domain: "L3/acl".to_string(),
                    detail: format!("{} ACL", config.acls.len()),
                });
            }
            if !config.nat.is_empty() {
                out.push(DomainMismatch {
                    domain: "L3/nat".to_string(),
                    detail: format!("{} правил NAT", config.nat.len()),
                });
            }
            let hsrp_count: usize = config.interfaces.iter().map(|i| i.hsrp.len()).sum();
            if hsrp_count > 0 {
                out.push(DomainMismatch {
                    domain: "L3/hsrp".to_string(),
                    detail: format!("{} групп HSRP", hsrp_count),
                });
            }
        }
        DeviceProfile::L3Router => {
            if !config.vlans.is_empty() {
                out.push(DomainMismatch {
                    domain: "L2/vlan".to_string(),
                    detail: format!("{} VLAN в базе", config.vlans.len()),
                });
            }
            if config.stp.is_some() {
                out.push(DomainMismatch {
                    domain: "L2/stp".to_string(),
                    detail: "глобальная конфигурация STP".to_string(),
                });
            }
            let l2_iface_count = config.interfaces.iter().filter(|i| i.l2.is_some()).count();
            if l2_iface_count > 0 {
                out.push(DomainMismatch {
                    domain: "L2/switchport".to_string(),
                    detail: format!(
                        "{} интерфейсов в режиме switchport (access/trunk)",
                        l2_iface_count
                    ),
                });
            }
            let voice_vlan_count = config.interfaces.iter().filter(|i| i.voice_vlan.is_some()).count();
            if voice_vlan_count > 0 {
                out.push(DomainMismatch {
                    domain: "L2/voice-vlan".to_string(),
                    detail: format!("{} интерфейсов с voice VLAN", voice_vlan_count),
                });
            }
        }
    }

    out
}
