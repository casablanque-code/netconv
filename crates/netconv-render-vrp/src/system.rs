use netconv_core::ir::*;
use netconv_core::report::ConversionReport;

pub fn render_system(cfg: &NetworkConfig, out: &mut Vec<String>, report: &mut ConversionReport) {
    render_hostname(cfg, out, report);
    render_dns(cfg, out, report);
    render_ntp(cfg, out, report);
    render_snmp(cfg, out, report);
    render_stp(cfg, out, report);
    render_users(cfg, out, report);
    render_ssh(cfg, out, report);
    render_line_vty(cfg, out, report);
    render_logging(cfg, out, report);
    render_platform_specific(cfg, out);
}

fn render_hostname(cfg: &NetworkConfig, out: &mut Vec<String>, report: &mut ConversionReport) {
    if let Some(hostname) = &cfg.hostname {
        out.push(format!("sysname {}", hostname));
        report.add_exact("system", &format!("hostname {}", hostname), &format!("sysname {}", hostname));
        out.push(String::new());
    }
}

fn render_dns(cfg: &NetworkConfig, out: &mut Vec<String>, report: &mut ConversionReport) {
    if cfg.dns.is_empty() { return; }
    out.push("dns resolve".to_string());
    for dns in &cfg.dns {
        out.push(format!("dns server {}", dns));
        report.add_exact("dns", &format!("ip name-server {}", dns), &format!("dns server {}", dns));
    }
    out.push(String::new());
}

fn render_ntp(cfg: &NetworkConfig, out: &mut Vec<String>, report: &mut ConversionReport) {
    if cfg.ntp.is_empty() { return; }
    for ntp in &cfg.ntp {
        let prefer_str = if ntp.prefer { " preference" } else { "" };
        let src = format!("ntp server {}{}", ntp.address, if ntp.prefer { " prefer" } else { "" });
        let dst = format!("ntp-service unicast-server {}{}", ntp.address, prefer_str);
        out.push(dst.clone());
        report.add_exact("ntp", &src, &dst);
    }
    out.push(String::new());
}

fn render_snmp(cfg: &NetworkConfig, out: &mut Vec<String>, report: &mut ConversionReport) {
    let snmp = match &cfg.snmp { Some(s) => s, None => return };
    out.push("snmp-agent".to_string());
    for comm in &snmp.communities {
        let (vrp_access, ios_access) = match comm.access {
            SnmpAccess::Ro => ("read", "RO"),
            SnmpAccess::Rw => ("write", "RW"),
        };
        let src = format!("snmp-server community {} {}", comm.name, ios_access);
        let dst = format!("snmp-agent community {} {}", vrp_access, comm.name);
        out.push(dst.clone());
        report.add_exact("snmp", &src, &dst);
    }
    if let Some(loc) = &snmp.location {
        let dst = format!("snmp-agent sys-info location {}", loc);
        out.push(dst.clone());
        report.add_exact("snmp", &format!("snmp-server location {}", loc), &dst);
    }
    if let Some(contact) = &snmp.contact {
        let dst = format!("snmp-agent sys-info contact {}", contact);
        out.push(dst.clone());
        report.add_exact("snmp", &format!("snmp-server contact {}", contact), &dst);
    }
    out.push(String::new());
}

fn render_stp(cfg: &NetworkConfig, out: &mut Vec<String>, report: &mut ConversionReport) {
    let stp = match &cfg.stp { Some(s) => s, None => return };

    out.push("#".to_string());

    // Cisco: spanning-tree mode rapid-pvst
    // VRP:   stp mode rstp  (VRP называет RSTP то что Cisco называет rapid-pvst per-vlan)
    let (vrp_mode, ios_mode) = match stp.mode {
        StpMode::RapidPvst => ("rstp",  "rapid-pvst"),
        StpMode::Pvst      => ("stp",   "pvst"),
        StpMode::Mst       => ("mstp",  "mst"),
        StpMode::Rstp      => ("rstp",  "rstp"),
    };
    out.push(format!("stp mode {}", vrp_mode));
    report.add_approximate(
        "stp.mode",
        &format!("spanning-tree mode {}", ios_mode),
        &format!("stp mode {}", vrp_mode),
        "VRP: rapid-pvst → rstp. На Huawei RSTP работает per-port, не per-vlan как у Cisco PVST+. \
         Для per-vlan STP используй MSTP.",
    );

    if stp.loopguard {
        out.push("stp loop-protection".to_string());
        report.add_approximate(
            "stp.loopguard",
            "spanning-tree loopguard default",
            "stp loop-protection",
            "VRP: stp loop-protection — аналог loopguard",
        );
    }

    if stp.bpduguard_default {
        out.push("stp bpdu-protection".to_string());
        report.add_approximate(
            "stp.bpduguard",
            "spanning-tree portfast bpduguard default",
            "stp bpdu-protection",
            "VRP: stp bpdu-protection глобально. На интерфейсах с portfast — применится автоматически.",
        );
    }

    // VLAN priorities
    for vp in &stp.vlan_priorities {
        // Cisco PVST: spanning-tree vlan X priority Y — per-vlan
        // VRP MSTP: stp instance X priority Y — нет прямого per-vlan аналога в RSTP
        let vlan_str = vp.vlans.iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join(",");
        out.push(format!("# MANUAL: spanning-tree vlan {} priority {} →", vlan_str, vp.priority));
        out.push(format!("#   В RSTP нет per-vlan приоритетов. Используй MSTP:"));
        out.push(format!("#   stp instance 0 priority {}", vp.priority));
        report.add_manual(
            "stp.vlan_priority",
            &format!("spanning-tree vlan {} priority {}", vlan_str, vp.priority),
            "Per-vlan STP priority недоступен в RSTP режиме VRP",
            Some("Перейди на MSTP (stp mode mstp) и настрой instance priority"),
        );
    }

    out.push(String::new());
}

fn render_users(cfg: &NetworkConfig, out: &mut Vec<String>, report: &mut ConversionReport) {
    if cfg.users.is_empty() { return; }

    out.push("#".to_string());
    out.push("# Local users".to_string());

    for user in &cfg.users {
        // Cisco: username root privilege 15 secret 5 HASH
        // VRP:   local-user root password irreversible-cipher HASH
        //        local-user root privilege level 15
        //        local-user root service-type ssh terminal

        let pw_note = match user.password_type {
            PasswordType::Type7  =>
                "Cisco Type 7 — обратимое шифрование. Пароль нужно ввести заново в открытом виде.",
            PasswordType::Md5    =>
                "Cisco MD5 (secret 5) — нельзя расшифровать. Задай новый пароль вручную.",
            PasswordType::Scrypt =>
                "Cisco scrypt (secret 9) — нельзя расшифровать. Задай новый пароль вручную.",
            PasswordType::Plaintext => "Пароль в открытом виде — задай на VRP.",
        };

        out.push(format!("local-user {} password irreversible-cipher <НОВЫЙ-ПАРОЛЬ>", user.name));
        out.push(format!("local-user {} privilege level {}", user.name, user.privilege));
        out.push(format!("local-user {} service-type ssh terminal", user.name));

        report.add_manual(
            "user",
            &format!("username {} privilege {}", user.name, user.privilege),
            pw_note,
            Some(&format!("local-user {} password irreversible-cipher <ПАРОЛЬ>", user.name)),
        );
    }

    out.push(String::new());
}

fn render_ssh(cfg: &NetworkConfig, out: &mut Vec<String>, report: &mut ConversionReport) {
    let ssh = match &cfg.ssh { Some(s) => s, None => return };

    out.push("#".to_string());
    // Cisco: ip ssh version 2
    // VRP:   stelnet server enable + ssh server-source (на интерфейсе)
    out.push("stelnet server enable".to_string());
    out.push(format!("ssh server-source -i all"));  // all interfaces
    if ssh.version >= 2 {
        out.push("undo ssh server compatible-ssh1x enable".to_string());
    }
    report.add_approximate(
        "ssh",
        &format!("ip ssh version {}", ssh.version),
        "stelnet server enable",
        "VRP: stelnet server enable включает SSH. \
         'undo ssh server compatible-ssh1x' отключает SSHv1 совместимость.",
    );
    out.push(String::new());
}

fn render_line_vty(cfg: &NetworkConfig, out: &mut Vec<String>, report: &mut ConversionReport) {
    let vty = match &cfg.line_vty { Some(v) => v, None => return };

    out.push("#".to_string());
    // Cisco: line vty 0 4 / exec-timeout 120 0 / transport input ssh
    // VRP:   user-interface vty 0 4 / idle-timeout 120 0 / protocol inbound ssh
    out.push("user-interface vty 0 4".to_string());

    if vty.exec_timeout_min > 0 || vty.exec_timeout_sec > 0 {
        out.push(format!(" idle-timeout {} {}", vty.exec_timeout_min, vty.exec_timeout_sec));
        report.add_approximate(
            "line_vty.timeout",
            &format!("exec-timeout {} {}", vty.exec_timeout_min, vty.exec_timeout_sec),
            &format!("idle-timeout {} {}", vty.exec_timeout_min, vty.exec_timeout_sec),
            "VRP: idle-timeout вместо exec-timeout",
        );
    }

    for proto in &vty.transport_input {
        let vrp_proto = match proto.as_str() {
            "ssh"    => "ssh",
            "telnet" => "telnet",
            "all"    => "all",
            _        => continue,
        };
        out.push(format!(" protocol inbound {}", vrp_proto));
        report.add_approximate(
            "line_vty.transport",
            &format!("transport input {}", proto),
            &format!("protocol inbound {}", vrp_proto),
            "VRP: 'protocol inbound' вместо 'transport input'",
        );
    }

    if vty.logging_synchronous {
        // VRP не имеет прямого аналога — logging synchronous специфично для Cisco
        out.push(" # logging synchronous — нет аналога на VRP".to_string());
    }

    out.push(String::new());
}

fn render_logging(cfg: &NetworkConfig, out: &mut Vec<String>, report: &mut ConversionReport) {
    let logging = match &cfg.logging { Some(l) => l, None => return };

    out.push("#".to_string());

    if let Some(size) = logging.buffered_size {
        // Cisco: logging buffered 16386
        // VRP:   info-center logbuffer size 16386
        out.push(format!("info-center logbuffer size {}", size));
        report.add_approximate(
            "logging.buffered",
            &format!("logging buffered {}", size),
            &format!("info-center logbuffer size {}", size),
            "VRP: info-center logbuffer size — аналог logging buffered",
        );
    }

    for host in &logging.hosts {
        out.push(format!("info-center loghost {}", host));
        report.add_approximate(
            "logging.host",
            &format!("logging {}", host),
            &format!("info-center loghost {}", host),
            "VRP: info-center loghost вместо logging <host>",
        );
    }

    out.push(String::new());
}

fn render_platform_specific(cfg: &NetworkConfig, out: &mut Vec<String>) {
    if cfg.platform_specific.is_empty() { return; }
    out.push("#".to_string());
    out.push("# ============================================================".to_string());
    out.push("# ПЛАТФОРМО-СПЕЦИФИЧНЫЕ КОМАНДЫ (нет аналога на VRP):".to_string());
    out.push("# ============================================================".to_string());
    for block in &cfg.platform_specific {
        out.push(format!("# [line {}] {}", block.line, block.raw));
    }
    out.push(String::new());
}
