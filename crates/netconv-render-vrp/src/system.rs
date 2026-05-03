use netconv_core::ir::*;
use netconv_core::report::ConversionReport;

pub fn render_system(cfg: &NetworkConfig, out: &mut Vec<String>, report: &mut ConversionReport) {
    // sysname (аналог hostname)
    if let Some(hostname) = &cfg.hostname {
        out.push(format!("sysname {}", hostname));
        report.add_exact("system", &format!("hostname {}", hostname), &format!("sysname {}", hostname));
        out.push(String::new());
    }

    // DNS
    if !cfg.dns.is_empty() {
        for dns in &cfg.dns {
            let src = format!("ip name-server {}", dns);
            let _dst = format!("dns resolve\ndns server {}", dns);
            out.push("dns resolve".to_string());
            out.push(format!("dns server {}", dns));
            report.add_exact("dns", &src, &format!("dns server {}", dns));
        }
        out.push(String::new());
    }

    // NTP
    if !cfg.ntp.is_empty() {
        for ntp in &cfg.ntp {
            // Cisco: ntp server 1.2.3.4 prefer
            // VRP:   ntp-service unicast-server 1.2.3.4 [preference]
            let prefer_str = if ntp.prefer { " preference" } else { "" };
            let src = format!("ntp server {}{}", ntp.address,
                if ntp.prefer { " prefer" } else { "" });
            let dst = format!("ntp-service unicast-server {}{}", ntp.address, prefer_str);
            out.push(dst.clone());
            report.add_exact("ntp", &src, &dst);
        }
        out.push(String::new());
    }

    // SNMP
    if let Some(snmp) = &cfg.snmp {
        out.push("snmp-agent".to_string());

        for comm in &snmp.communities {
            // Cisco: snmp-server community public RO
            // VRP:   snmp-agent community read public
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
            let src = format!("snmp-server location {}", loc);
            let dst = format!("snmp-agent sys-info location {}", loc);
            out.push(dst.clone());
            report.add_exact("snmp", &src, &dst);
        }

        if let Some(contact) = &snmp.contact {
            let src = format!("snmp-server contact {}", contact);
            let dst = format!("snmp-agent sys-info contact {}", contact);
            out.push(dst.clone());
            report.add_exact("snmp", &src, &dst);
        }

        out.push(String::new());
    }
}
