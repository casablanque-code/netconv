use netconv_core::ir::*;
use netconv_core::report::ConversionReport;

pub fn render_system(cfg: &NetworkConfig, out: &mut Vec<String>, report: &mut ConversionReport) {
    render_hostname(cfg, out, report);
    render_ntp(cfg, out, report);
    render_snmp(cfg, out, report);
    render_users(cfg, out, report);
    render_ssh(cfg, out, report);
    render_logging(cfg, out, report);
    render_aaa_note(cfg, out, report);
}

fn render_hostname(cfg: &NetworkConfig, out: &mut Vec<String>, report: &mut ConversionReport) {
    if let Some(hostname) = &cfg.hostname {
        // ESR: hostname <name>  (как у Cisco, 1:1)
        out.push(format!("hostname {}", hostname));
        report.add_exact(
            "system",
            &format!("hostname {}", hostname),
            &format!("hostname {}", hostname),
        );
        out.push(String::new());
    }
}

fn render_ntp(cfg: &NetworkConfig, out: &mut Vec<String>, report: &mut ConversionReport) {
    if cfg.ntp.is_empty() { return; }
    for ntp in &cfg.ntp {
        // Cisco: ntp server 1.2.3.4 prefer
        // ESR:   ntp server 1.2.3.4
        //        ntp prefer 1.2.3.4  (prefer — отдельная команда)
        let src = format!("ntp server {}{}", ntp.address, if ntp.prefer { " prefer" } else { "" });
        out.push(format!("ntp server {}", ntp.address));
        if ntp.prefer {
            out.push(format!("ntp prefer {}", ntp.address));
        }
        let dst = format!("ntp server {}", ntp.address);
        report.add_exact("ntp", &src, &dst);
    }
    out.push(String::new());
}

fn render_snmp(cfg: &NetworkConfig, out: &mut Vec<String>, report: &mut ConversionReport) {
    let snmp = match &cfg.snmp { Some(s) => s, None => return };

    let vrp_reserved = ["read", "write", "trap", "all"];

    for comm in &snmp.communities {
        let ios_access = match comm.access { SnmpAccess::Ro => "RO", SnmpAccess::Rw => "RW" };
        let esr_access = match comm.access { SnmpAccess::Ro => "ro", SnmpAccess::Rw => "rw" };

        let src = format!("snmp-server community {} {}", comm.name, ios_access);

        if vrp_reserved.contains(&comm.name.to_lowercase().as_str()) {
            out.push(format!("! MANUAL: community name '{}' may conflict — rename:", comm.name));
            out.push(format!("! snmp-server community <new-name> {}", esr_access));
            report.add_manual(
                "snmp.community",
                &src,
                &format!("community name '{}' conflicts with reserved keyword", comm.name),
                Some(&format!("snmp-server community <new-name> {}", esr_access)),
            );
        } else {
            // ESR: snmp-server community <name> ro|rw
            let dst = format!("snmp-server community {} {}", comm.name, esr_access);
            out.push(dst.clone());
            report.add_exact("snmp", &src, &dst);
        }
    }

    if let Some(loc) = &snmp.location {
        out.push(format!("snmp-server location {}", loc));
        report.add_exact("snmp", &format!("snmp-server location {}", loc),
            &format!("snmp-server location {}", loc));
    }

    if let Some(contact) = &snmp.contact {
        out.push(format!("snmp-server contact {}", contact));
        report.add_exact("snmp", &format!("snmp-server contact {}", contact),
            &format!("snmp-server contact {}", contact));
    }

    out.push(String::new());
}

fn render_users(cfg: &NetworkConfig, out: &mut Vec<String>, report: &mut ConversionReport) {
    if cfg.users.is_empty() { return; }

    for user in &cfg.users {
        if user.name == "enable" {
            out.push("! MANUAL: Cisco enable secret — no direct equivalent on ESR.".to_string());
            out.push("!   Configure privileged user manually:".to_string());
            out.push("!   username admin".to_string());
            out.push("!    password <PASSWORD>".to_string());
            out.push("!    privilege 15".to_string());
            out.push("!    exit".to_string());
            continue;
        }

        let pw_note = match user.password_type {
            PasswordType::Type7     => "Cisco Type 7 (reversible) — enter plaintext password",
            PasswordType::Md5       => "Cisco MD5 — cannot decrypt, set new password",
            PasswordType::Scrypt    => "Cisco scrypt — cannot decrypt, set new password",
            PasswordType::Plaintext => "Set password",
        };

        // ESR user config блок
        out.push(format!("username {}", user.name));
        out.push(format!(" password <NEW-PASSWORD>  ! {}", pw_note));
        out.push(format!(" privilege {}", user.privilege));
        out.push(" exit".to_string());

        report.add_manual(
            "user",
            &format!("username {} privilege {}", user.name, user.privilege),
            pw_note,
            Some(&format!("username {} / password <PASS> / privilege {}", user.name, user.privilege)),
        );
    }
    out.push(String::new());
}

fn render_ssh(cfg: &NetworkConfig, out: &mut Vec<String>, report: &mut ConversionReport) {
    let ssh = match &cfg.ssh { Some(s) => s, None => return };
    // ESR: ssh server — включён по умолчанию если есть пользователи
    // ip ssh version 2 → на ESR SSHv2 по умолчанию
    out.push("! SSH: enabled by default on ESR when users are configured.".to_string());
    if ssh.version >= 2 {
        out.push("! SSHv2 is the default on ESR — no additional configuration needed.".to_string());
    }
    report.add_approximate(
        "ssh",
        &format!("ip ssh version {}", ssh.version),
        "# SSH enabled by default",
        "ESR: SSH включён по умолчанию при наличии пользователей. SSHv2 — дефолтный.",
    );
    out.push(String::new());
}

fn render_logging(cfg: &NetworkConfig, out: &mut Vec<String>, report: &mut ConversionReport) {
    let logging = match &cfg.logging { Some(l) => l, None => return };
    if let Some(size) = logging.buffered_size {
        // ESR: syslog file-size <KB>  (в КБ, не в байтах)
        let size_kb = std::cmp::max(1, size / 1024);
        out.push(format!("syslog file-size {}", size_kb));
        report.add_approximate(
            "logging",
            &format!("logging buffered {}", size),
            &format!("syslog file-size {}", size_kb),
            &format!("ESR syslog file-size в КБ. {} bytes → {} KB", size, size_kb),
        );
    }
    for host in &logging.hosts {
        out.push(format!("syslog host {}", host));
        report.add_approximate(
            "logging.host",
            &format!("logging {}", host),
            &format!("syslog host {}", host),
            "ESR: syslog host вместо logging",
        );
    }
    if !cfg.logging.as_ref().map(|l| l.hosts.is_empty()).unwrap_or(true)
        || logging.buffered_size.is_some() {
        out.push(String::new());
    }
}

fn render_aaa_note(cfg: &NetworkConfig, out: &mut Vec<String>, report: &mut ConversionReport) {
    let aaa = match &cfg.aaa { Some(a) => a, None => return };
    if !aaa.new_model { return; }

    out.push("! MANUAL: AAA configuration".to_string());
    out.push("!   Source used 'aaa new-model'. On ESR configure authentication via:".to_string());
    out.push("!   aaa authentication login default local".to_string());
    out.push("!   (or radius/tacacs+ if external auth required)".to_string());
    report.add_manual(
        "aaa",
        "aaa new-model",
        "AAA requires manual setup on ESR",
        Some("aaa authentication login default local"),
    );
    out.push(String::new());
}
