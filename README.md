# letsdefend-soc-investigations
SOC analyst and incident response investigations from LetsDefend: phishing, web attacks, Log4Shell, privilege escalation. Mapped to MITRE ATT&amp;CK with evidence and IOCs.
# 🛡️ SOC Investigations – LetsDefend Write-ups

**Sidharth V Nambiar** · CompTIA Security+ · Griffith University
Hands-on SOC analyst and incident responder investigations from the [LetsDefend](https://letsdefend.io) SOC simulator (Hack The Box). Each case is triaged with SIEM, EDR, email security and threat intel, mapped to MITRE ATT&CK, and documented end to end.

## 📊 Investigations

| Alert | Category | Severity | Verdict | Highlights |
|---|---|---|---|---|
| [SOC337 – Lazarus Phishing Campaign (APT38)](SOC337/) | Phishing | High | TP, contained | Fake crypto job offer → malicious link → PowerShell payload; nation-state attribution |
| [SOC338 – Lumma Stealer via ClickFix](SOC338/) | Phishing / Malware | Critical | TP, contained | Fake reCAPTCHA → Run dialog → obfuscated PowerShell → mshta payload |
| [SOC342 – SharePoint ToolShell (CVE-2025-53770)](SOC342/) | Web exploit (0-day) | Critical | TP, contained + escalated | Unauthenticated RCE → web shell → MachineKey theft |
| [SOC165 – SQL Injection](SOC165/) | Web attack | High | TP, unsuccessful | Decoded `OR 1=1` payloads; HTTP 500 / same size proved failure |
| [SOC168 – Command Injection (whoami)](SOC168/) | Web attack | High | TP, successful + escalated | EDR terminal history confirmed `cat /etc/shadow` |
| [SOC166 – Cross-Site Scripting (XSS)](SOC166/) | Web attack | Medium | TP, unsuccessful | 4 payload variants; HTTP 302 / 0 bytes = not reflected |
| [SOC161 – Log4Shell (CVE-2021-44228)](SOC161/) | RCE (Incident Responder) | Critical | TP, isolated | JNDI in chat → LDAP callback → remote Java class executed |
| [SOC299 – UAC Bypass](SOC299/) ⭐ | Privilege escalation (Incident Responder) | High | TP, successful | RDP brute force → in-memory WinPwn → DiskCleanup UAC bypass → backdoor account |

⭐ **Toughest case:** SOC299, a full attack chain from initial access to persistence.

## 🔍 How I investigate
1. **Triage:** read the alert, the L1 note and the MITRE tags
2. **Decode:** URL/Base64 payloads in CyberChef
3. **Logs:** pivot on the source IP in the SIEM (status codes, response sizes, Windows Event IDs)
4. **Endpoint:** EDR processes, network connections, terminal and browser history
5. **Threat intel:** VirusTotal, AbuseIPDB, LetsDefend TI
6. **Decide:** True/False Positive, and whether the attack *succeeded*
7. **Respond:** contain, escalate, eradicate, document IOCs

## 🧠 Key lessons
- "Malicious" and "successful" are two different questions
- Always decode before judging
- HTTP status + response size reveal web-attack success
- Many 4625s followed by a 4624 = brute force success
- Fileless attacks still leave command lines and network traces

## 🧰 Tools
LetsDefend SIEM · EDR · Email Security · CyberChef · VirusTotal · AbuseIPDB · MITRE ATT&CK

## 📁 Structure
```
SOCxxx/
├── README.md        # full investigation write-up
└── screenshots/     # evidence images
```

---
*All cases are from a training environment. Indicators are defanged.*
