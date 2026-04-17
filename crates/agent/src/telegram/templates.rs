use super::formatting::escape_html;

/// Return a 2-3 sentence plain explanation for a detector.
/// Used when simple-profile users tap "What does this mean?"
pub fn explain_detector(detector: &str) -> String {
    let text = match detector {
        "ssh_bruteforce" => "This means someone from another country tried to log into your server by guessing passwords. This is very common on the internet and happens to every server. InnerWarden blocked them automatically. You don't need to do anything.",
        "credential_stuffing" => "This means someone used a list of stolen passwords from other websites to try to log in to your server. These passwords were leaked in data breaches. InnerWarden detected the pattern and stopped it.",
        "port_scan" => "Someone is checking which services are running on your server. This is like someone walking around a building trying every door. It's a common first step before an attack. InnerWarden is keeping watch.",
        "packet_flood" => "Your server received a large amount of network traffic in a short time. This could be an attempt to overwhelm your server (DDoS attack). InnerWarden is managing the traffic.",
        "data_exfil" | "data_exfil_cmd" | "data_exfil_ebpf" => "A program on your server tried to send sensitive data (like passwords or configuration files) to an external location. This could mean an attacker is trying to steal information. InnerWarden caught it.",
        "reverse_shell" => "An attacker may have established a way to remotely control your server. This is a serious threat where someone can execute commands as if they were sitting at the keyboard. InnerWarden is taking action.",
        "privesc" => "A program tried to gain administrator (root) access without proper authorization. This usually means an attacker is trying to take full control of your server. InnerWarden blocked the attempt.",
        "rootkit" => "Suspicious activity was detected at the deepest level of your operating system (the kernel). Rootkits try to hide malicious software from detection tools. This is a serious threat that InnerWarden is monitoring closely.",
        "ransomware" => "A pattern consistent with ransomware was detected. Ransomware encrypts your files and demands payment to unlock them. InnerWarden detected this early to prevent damage.",
        "dns_tunneling" | "dns_tunneling_ebpf" => "A program is using the DNS system (which translates domain names to addresses) to secretly send or receive data. Attackers use this to bypass firewalls. InnerWarden detected the hidden channel.",
        "c2_callback" => "Your server appears to be communicating with a known attacker-controlled server (called 'command and control'). This could mean malware is receiving instructions. InnerWarden is intervening.",
        "crypto_miner" => "Something on your server is using CPU power to mine cryptocurrency. This steals your computing resources and increases your electricity costs. InnerWarden detected the unauthorized mining.",
        "container_escape" => "A containerized application tried to access resources outside its isolated environment. Containers are supposed to be sandboxed. This could be an attack attempting to reach the host system.",
        "lateral_movement" => "An attacker is trying to move from one system or account to another within your network. This is how attackers spread after their initial break-in. InnerWarden detected the movement.",
        "web_shell" => "A web-based backdoor was found on your server. Web shells allow attackers to run commands through a web page. This usually means an attacker uploaded a malicious file to your web server.",
        "process_injection" => "A program tried to insert its code into another running program. Attackers do this to hide their activity inside legitimate software. InnerWarden caught the injection attempt.",
        "fileless" => "Malware was detected running entirely in memory without writing to disk. This technique is used to avoid antivirus detection. InnerWarden's memory analysis caught it.",
        "log_tampering" => "Someone tried to delete or modify system logs. Attackers do this to cover their tracks after breaking in. InnerWarden preserves the evidence and detected the tampering.",
        "ssh_key_injection" => "An SSH key was added to your server's authorized keys. This would allow someone to log in without a password in the future. If you didn't do this, an attacker is setting up persistent access.",
        "crontab_persistence" | "systemd_persistence" => "Something installed a scheduled task or service that will start automatically, even after a reboot. Attackers use this to maintain access to your server long-term. InnerWarden is monitoring it.",
        "kernel_module_load" => "A new kernel module was loaded into your operating system's core. While some modules are legitimate (drivers, etc.), malicious modules can give attackers deep system access. InnerWarden is checking it.",
        "discovery_burst" => "Someone is running commands to map out your system, listing users, files, network connections, and installed software. This is reconnaissance, usually done after an initial break-in. InnerWarden is watching.",
        "sigma" => "A known attack pattern from the security community's signature database was matched. These patterns are maintained by security researchers worldwide. InnerWarden recognized the threat.",
        "suspicious_execution" => "A program was executed that matches patterns commonly seen in attacks. This could be a legitimate tool being misused or actual malware. InnerWarden is investigating.",
        "sensitive_write" => "An important system file (like password files or security configurations) was modified. If this wasn't a planned change, it could indicate an attacker modifying your system.",
        "user_creation" => "A new user account was created on your server. If you didn't create it, this could mean an attacker is setting up their own access. InnerWarden is tracking it.",
        "process_tree" => "A suspicious chain of programs was detected. For example, a web server launching a command shell is unusual and often indicates exploitation. InnerWarden noticed the suspicious chain.",
        "neural_anomaly" => "InnerWarden's AI detected behavior that doesn't match your server's normal patterns. Machine learning identified something unusual that rule-based detection might miss.",
        _ => "InnerWarden detected suspicious activity on your server. The system is monitoring the situation and will take appropriate action based on your settings.",
    };
    format!(
        "\u{2139}\u{fe0f} <b>What does this mean?</b>\n\n{}",
        escape_html(text)
    )
}
