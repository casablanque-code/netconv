use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

// ---------------------------------------------------------------------------
// Confidence — каждый элемент IR знает насколько точно он был распознан
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Confidence {
    /// Точное соответствие — гарантировано корректная конвертация
    Exact,
    /// Есть аналог, но с нюансами — объясняем в репорте
    Approximate { note: String },
    /// Нет аналога на целевой платформе — требует ручного решения
    Manual { reason: String },
    /// Парсер не распознал команду — сохраняем raw текст
    Unknown { raw: String },
}

// ---------------------------------------------------------------------------
// NetworkConfig — корневой объект IR
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub hostname: Option<String>,
    pub domain_name: Option<String>,
    pub interfaces: Vec<Interface>,
    pub vlans: Vec<Vlan>,
    pub routing: RoutingConfig,
    pub acls: Vec<Acl>,
    pub nat: Vec<NatRule>,
    pub ntp: Vec<NtpServer>,
    pub dns: Vec<IpAddr>,
    pub snmp: Option<SnmpConfig>,
    pub aaa: Option<AaaConfig>,
    pub banner: Option<String>,
    /// Всё что парсер не распознал — не выбрасываем, храним
    pub unknown_blocks: Vec<UnknownBlock>,
}

// ---------------------------------------------------------------------------
// Interface
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Interface {
    /// Нормализованное имя: "GigabitEthernet0/0" → "GigabitEthernet0/0"
    /// Рендерер сам адаптирует под целевой вендор
    pub name: InterfaceName,
    pub description: Option<String>,
    pub addresses: Vec<IpAddress>,
    pub shutdown: bool,
    pub mtu: Option<u32>,
    pub speed: Option<InterfaceSpeed>,
    pub duplex: Option<Duplex>,
    pub l2: Option<L2Config>,
    pub helper_addresses: Vec<IpAddr>,
    pub acl_in: Option<String>,
    pub acl_out: Option<String>,
    pub nat_direction: Option<NatDirection>,
    pub hsrp: Vec<HsrpGroup>,
    pub ospf: Option<InterfaceOspf>,
    pub confidence: Confidence,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceName {
    pub kind: InterfaceKind,
    /// Слот/порт как строка — "0/0", "0/0/0", "1" и т.д.
    pub id: String,
    /// Оригинальное имя из конфига — для репорта
    pub original: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum InterfaceKind {
    GigabitEthernet,
    FastEthernet,
    TenGigabitEthernet,
    Loopback,
    Vlan,
    Tunnel,
    Serial,
    BundleEther,
    Management,
    Unknown(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpAddress {
    pub prefix: IpNet,
    pub secondary: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InterfaceSpeed {
    Mbps(u32),
    Auto,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Duplex {
    Full,
    Half,
    Auto,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L2Config {
    pub mode: L2Mode,
    pub access_vlan: Option<u16>,
    pub trunk_allowed: Option<Vec<u16>>,
    pub trunk_native: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum L2Mode {
    Access,
    Trunk,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum NatDirection {
    Inside,
    Outside,
}

// ---------------------------------------------------------------------------
// HSRP → будет рендериться как VRRP на Huawei (Approximate)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HsrpGroup {
    pub group_id: u16,
    pub virtual_ip: IpAddr,
    pub priority: Option<u16>,
    pub preempt: bool,
    pub preempt_delay: Option<u32>,
    pub timers: Option<HsrpTimers>,
    pub track: Vec<HsrpTrack>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HsrpTimers {
    pub hello_ms: u32,
    pub hold_ms: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HsrpTrack {
    pub object: u32,
    pub decrement: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceOspf {
    pub process_id: u32,
    pub area: OspfArea,
    pub cost: Option<u32>,
    pub priority: Option<u8>,
    pub timers: Option<OspfIfTimers>,
    pub auth: Option<OspfAuth>,
    pub passive: bool,
    pub network_type: Option<OspfNetworkType>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OspfIfTimers {
    pub hello_interval: u32,
    pub dead_interval: u32,
}

// ---------------------------------------------------------------------------
// VLAN
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vlan {
    pub id: u16,
    pub name: Option<String>,
    pub active: bool,
}

// ---------------------------------------------------------------------------
// Routing
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RoutingConfig {
    pub static_routes: Vec<StaticRoute>,
    pub ospf: Vec<OspfProcess>,
    pub bgp: Option<BgpConfig>,
    pub eigrp: Vec<EigrpProcess>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticRoute {
    pub prefix: IpNet,
    pub next_hop: NextHop,
    pub distance: Option<u8>,
    pub tag: Option<u32>,
    pub name: Option<String>,
    pub permanent: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NextHop {
    Ip(IpAddr),
    Interface(String),
    IpAndInterface(IpAddr, String),
    Null0,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OspfProcess {
    pub process_id: u32,
    pub router_id: Option<IpAddr>,
    pub areas: Vec<OspfAreaConfig>,
    pub passive_interfaces: Vec<String>,
    pub default_originate: Option<OspfDefaultOriginate>,
    pub redistribute: Vec<OspfRedistribute>,
    pub max_metric: bool,
    pub auth: Option<OspfAuth>,
    pub log_adjacency: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OspfAreaConfig {
    pub area: OspfArea,
    pub networks: Vec<OspfNetwork>,
    pub area_type: OspfAreaType,
    pub auth: Option<OspfAuth>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum OspfArea {
    Backbone,           // area 0
    Normal(u32),
    IpFormat(IpAddr),  // area 0.0.0.1 формат
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OspfNetwork {
    pub prefix: IpNet,
    pub wildcard: bool, // если true — это wildcard маска, не prefix length
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum OspfAreaType {
    Normal,
    Stub,
    StubNoSummary,
    Nssa,
    NssaNoSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OspfAuth {
    Simple(String),
    Md5 { key_id: u8, key: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OspfNetworkType {
    Broadcast,
    PointToPoint,
    PointToMultipoint,
    NonBroadcast,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OspfDefaultOriginate {
    pub always: bool,
    pub metric: Option<u32>,
    pub metric_type: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OspfRedistribute {
    pub source: RedistributeSource,
    pub metric: Option<u32>,
    pub metric_type: Option<u8>,
    pub subnets: bool,
    pub tag: Option<u32>,
    pub route_map: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RedistributeSource {
    Connected,
    Static,
    Bgp(u32),
    Eigrp(u32),
    Rip,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BgpConfig {
    pub asn: u32,
    pub router_id: Option<IpAddr>,
    pub neighbors: Vec<BgpNeighbor>,
    pub networks: Vec<IpNet>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BgpNeighbor {
    pub address: IpAddr,
    pub remote_as: u32,
    pub description: Option<String>,
    pub update_source: Option<String>,
    pub next_hop_self: bool,
    pub password: Option<String>,
    pub shutdown: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EigrpProcess {
    pub asn: u32,
    pub networks: Vec<OspfNetwork>,
    pub passive_interfaces: Vec<String>,
    pub redistribute: Vec<OspfRedistribute>,
}

// ---------------------------------------------------------------------------
// ACL
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Acl {
    pub name: AclName,
    pub acl_type: AclType,
    pub entries: Vec<AclEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AclName {
    Named(String),
    Numbered(u32),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AclType {
    Standard,   // только src IP
    Extended,   // src+dst+proto+port
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AclEntry {
    pub sequence: Option<u32>,
    pub action: AclAction,
    pub protocol: Option<AclProtocol>,
    pub src: AclMatch,
    pub dst: Option<AclMatch>,
    pub src_port: Option<AclPort>,
    pub dst_port: Option<AclPort>,
    pub established: bool,
    pub log: bool,
    pub remark: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AclAction {
    Permit,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AclProtocol {
    Ip,
    Tcp,
    Udp,
    Icmp,
    Esp,
    Ahp,
    Number(u8),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AclMatch {
    Any,
    Host(IpAddr),
    Network { addr: IpAddr, wildcard: IpAddr },
    Prefix(IpNet),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AclPort {
    Eq(u16),
    Ne(u16),
    Lt(u16),
    Gt(u16),
    Range(u16, u16),
}

// ---------------------------------------------------------------------------
// NAT
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatRule {
    pub rule_type: NatType,
    pub acl: Option<String>,
    pub pool: Option<NatPool>,
    pub interface_overload: bool,
    pub static_entry: Option<NatStaticEntry>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum NatType {
    Dynamic,   // source list ACL pool
    Overload,  // PAT
    Static,    // фиксированный маппинг
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatPool {
    pub name: String,
    pub start: IpAddr,
    pub end: IpAddr,
    pub prefix: Option<IpNet>,
    pub overload: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatStaticEntry {
    pub local: IpAddr,
    pub global: IpAddr,
    pub local_port: Option<u16>,
    pub global_port: Option<u16>,
    pub protocol: Option<AclProtocol>,
}

// ---------------------------------------------------------------------------
// NTP / DNS / SNMP / AAA
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NtpServer {
    pub address: IpAddr,
    pub prefer: bool,
    pub key: Option<u32>,
    pub source_interface: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnmpConfig {
    pub communities: Vec<SnmpCommunity>,
    pub location: Option<String>,
    pub contact: Option<String>,
    pub traps: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnmpCommunity {
    pub name: String,
    pub access: SnmpAccess,
    pub acl: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SnmpAccess {
    Ro,
    Rw,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AaaConfig {
    pub new_model: bool,
    pub authentication: Vec<AaaMethod>,
    pub authorization: Vec<AaaMethod>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AaaMethod {
    pub list_name: String,
    pub methods: Vec<String>,
}

// ---------------------------------------------------------------------------
// UnknownBlock — всё нераспознанное, с контекстом
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnknownBlock {
    /// Строка в исходном конфиге
    pub line: usize,
    /// Контекст: в каком блоке находилась команда
    pub context: String,
    /// Оригинальный текст
    pub raw: String,
}

// ---------------------------------------------------------------------------
// Вспомогательные типы
// ---------------------------------------------------------------------------

pub type ProcessId = u32;

impl Default for Interface {
    fn default() -> Self {
        Interface {
            name: InterfaceName {
                kind: InterfaceKind::Unknown(String::new()),
                id: String::new(),
                original: String::new(),
            },
            description: None,
            addresses: vec![],
            shutdown: false,
            mtu: None,
            speed: None,
            duplex: None,
            l2: None,
            helper_addresses: vec![],
            acl_in: None,
            acl_out: None,
            nat_direction: None,
            hsrp: vec![],
            ospf: None,
            confidence: Confidence::Exact,
        }
    }
}

impl InterfaceName {
    pub fn parse(raw: &str) -> Self {
        let original = raw.to_string();

        // Нормализуем сокращения Cisco
        let expanded = expand_interface_name(raw);

        // Разбиваем на kind + id
        let (kind_str, id) = split_interface_name(&expanded);

        let kind = match kind_str.to_lowercase().as_str() {
            "gigabitethernet" => InterfaceKind::GigabitEthernet,
            "fastethernet"    => InterfaceKind::FastEthernet,
            "tengigabitethernet" | "tengige" => InterfaceKind::TenGigabitEthernet,
            "loopback"        => InterfaceKind::Loopback,
            "vlan"            => InterfaceKind::Vlan,
            "tunnel"          => InterfaceKind::Tunnel,
            "serial"          => InterfaceKind::Serial,
            "bundle-ether" | "bundleether" => InterfaceKind::BundleEther,
            "management"      => InterfaceKind::Management,
            other             => InterfaceKind::Unknown(other.to_string()),
        };

        InterfaceName { kind, id, original }
    }
}

fn expand_interface_name(raw: &str) -> String {
    // Cisco сокращения → полные имена
    let prefixes = [
        ("Gi", "GigabitEthernet"),
        ("Fa", "FastEthernet"),
        ("Te", "TenGigabitEthernet"),
        ("Lo", "Loopback"),
        ("Tu", "Tunnel"),
        ("Se", "Serial"),
        ("Vl", "Vlan"),
        ("Mg", "Management"),
    ];

    for (short, full) in &prefixes {
        if raw.starts_with(short) && !raw.to_lowercase().starts_with(&full.to_lowercase()) {
            return format!("{}{}", full, &raw[short.len()..]);
        }
    }
    raw.to_string()
}

fn split_interface_name(name: &str) -> (&str, String) {
    // Ищем первую цифру — всё до неё это тип, после — id
    let pos = name.find(|c: char| c.is_ascii_digit());
    match pos {
        Some(i) => (&name[..i], name[i..].to_string()),
        None    => (name, String::new()),
    }
}

impl OspfArea {
    pub fn parse(s: &str) -> Self {
        if let Ok(n) = s.parse::<u32>() {
            if n == 0 {
                OspfArea::Backbone
            } else {
                OspfArea::Normal(n)
            }
        } else if let Ok(ip) = s.parse::<IpAddr>() {
            if ip == "0.0.0.0".parse::<IpAddr>().unwrap() {
                OspfArea::Backbone
            } else {
                OspfArea::IpFormat(ip)
            }
        } else {
            OspfArea::Normal(0) // fallback
        }
    }
}
