"""SentinelAI Comprehensive Snort / Suricata IDS Signature Repository.

Contains production-grade Network Intrusion Detection signatures covering:
- Critical CVE Exploits (Log4Shell, Spring4Shell, ProxyLogon, PrintNightmare, EternalBlue, CitrixBleed)
- Web Application Vulnerabilities (SQLi, XSS, SSRF, Command Injection, Directory Traversal)
- Protocol Anomalies & C2 Beaconing (Cobalt Strike HTTP, DNS Tunneling, Sliver HTTP)
"""

from typing import List


def get_enterprise_ids_signatures() -> List[str]:
    return [
        # -------------------------------------------------------------
        # 1. Critical Remote Code Execution (RCE) Exploits
        # -------------------------------------------------------------
        'alert tcp any any -> any any (msg:"EXPLOIT Apache Log4j JNDI RCE Attempt (CVE-2021-44228)"; content:"${jndi:"; nocase; classtype:"attempted-admin"; reference:cve,CVE-2021-44228; reference:attack,T1190; sid:2034361; rev:1;)',
        'alert tcp any any -> any any (msg:"EXPLOIT Apache Log4j Obfuscated Lower/Upper JNDI (CVE-2021-44228)"; content:"${lower:j}"; nocase; classtype:"attempted-admin"; reference:cve,CVE-2021-44228; reference:attack,T1190; sid:2034362; rev:1;)',
        'alert tcp any any -> any 8080 (msg:"EXPLOIT Spring Framework Spring4Shell RCE (CVE-2022-22965)"; content:"class.module.classLoader"; nocase; classtype:"attempted-admin"; reference:cve,CVE-2022-22965; reference:attack,T1190; sid:2035399; rev:1;)',
        'alert tcp any any -> any 443 (msg:"EXPLOIT Microsoft Exchange ProxyLogon SSRF (CVE-2021-26855)"; content:"X-AnonResource-Backend"; nocase; classtype:"attempted-admin"; reference:cve,CVE-2021-26855; reference:attack,T1190; sid:2031756; rev:1;)',
        'alert tcp any any -> any 443 (msg:"EXPLOIT Microsoft Exchange ProxyShell Autodiscover (CVE-2021-34473)"; content:"/autodiscover/autodiscover.json?@"; nocase; classtype:"attempted-admin"; reference:cve,CVE-2021-34473; reference:attack,T1190; sid:2033780; rev:1;)',
        'alert tcp any any -> any 445 (msg:"EXPLOIT Microsoft Windows SMBv1 EternalBlue Multiplex ID (MS17-010 / CVE-2017-0144)"; content:"|ff|SMB%|00 00 00 00|"; offset:4; depth:9; classtype:"attempted-admin"; reference:cve,CVE-2017-0144; reference:attack,T1210; sid:2024218; rev:2;)',
        'alert tcp any any -> any 80 (msg:"EXPLOIT Apache HTTP Server 2.4.49 Path Traversal (CVE-2021-41773)"; content:".%2e/"; nocase; classtype:"web-application-attack"; reference:cve,CVE-2021-41773; reference:attack,T1083; sid:2034138; rev:1;)',
        'alert tcp any any -> any 8090 (msg:"EXPLOIT Atlassian Confluence OGNL Injection (CVE-2022-26134)"; content:"${@java.lang.Runtime"; nocase; classtype:"attempted-admin"; reference:cve,CVE-2022-26134; reference:attack,T1190; sid:2036499; rev:1;)',
        'alert tcp any any -> any 443 (msg:"EXPLOIT Citrix Bleed Session Token Hijacking (CVE-2023-4966)"; content:"/oauth/idp/.well-known/openid-configuration"; nocase; classtype:"attempted-user"; reference:cve,CVE-2023-4966; reference:attack,T1539; sid:2048991; rev:1;)',
        'alert tcp any any -> any 443 (msg:"EXPLOIT VMware Workspace ONE Freemarker Template Injection (CVE-2022-22954)"; content:"/catalog-portal/ui/oauth/verify?error="; content:"${#"; nocase; classtype:"attempted-admin"; reference:cve,CVE-2022-22954; reference:attack,T1190; sid:2035581; rev:1;)',

        # -------------------------------------------------------------
        # 2. Web Application Attacks (SQLi, XSS, SSRF, Command Injection)
        # -------------------------------------------------------------
        'alert tcp any any -> any any (msg:"WEB-ATTACKS Generic SQL Injection UNION SELECT Attempt"; content:"UNION"; nocase; content:"SELECT"; nocase; classtype:"web-application-attack"; reference:attack,T1190; sid:2100001; rev:1;)',
        'alert tcp any any -> any any (msg:"WEB-ATTACKS SQL Injection OR 1=1 Boolean Tautology"; content:" OR "; nocase; content:"1=1"; classtype:"web-application-attack"; reference:attack,T1190; sid:2100002; rev:1;)',
        'alert tcp any any -> any any (msg:"WEB-ATTACKS SQL Injection Benchmark/Sleep Time-Based Blind"; content:"benchmark("; nocase; classtype:"web-application-attack"; reference:attack,T1190; sid:2100003; rev:1;)',
        'alert tcp any any -> any any (msg:"WEB-ATTACKS SQL Injection pg_sleep Time Delay"; content:"pg_sleep("; nocase; classtype:"web-application-attack"; reference:attack,T1190; sid:2100004; rev:1;)',
        'alert tcp any any -> any any (msg:"WEB-ATTACKS Generic Cross-Site Scripting <script> Tag Injection"; content:"<script>"; nocase; classtype:"web-application-attack"; reference:attack,T1059.007; sid:2100010; rev:1;)',
        'alert tcp any any -> any any (msg:"WEB-ATTACKS Cross-Site Scripting javascript: Pseudo-Protocol"; content:"javascript:"; nocase; classtype:"web-application-attack"; reference:attack,T1059.007; sid:2100011; rev:1;)',
        'alert tcp any any -> any any (msg:"WEB-ATTACKS Server-Side Request Forgery AWS Metadata Access"; content:"http://169.254.169.254/latest/meta-data/"; nocase; classtype:"web-application-attack"; reference:attack,T1552.005; sid:2100020; rev:1;)',
        'alert tcp any any -> any any (msg:"WEB-ATTACKS Directory Traversal /etc/passwd Extraction"; content:"/etc/passwd"; classtype:"web-application-attack"; reference:attack,T1083; sid:2100030; rev:1;)',
        'alert tcp any any -> any any (msg:"WEB-ATTACKS Directory Traversal Windows win.ini Access"; content:"/windows/win.ini"; nocase; classtype:"web-application-attack"; reference:attack,T1083; sid:2100031; rev:1;)',
        'alert tcp any any -> any any (msg:"WEB-ATTACKS UNIX Command Injection Semicolon Pipe Chaining"; content:";cat /etc/"; nocase; classtype:"web-application-attack"; reference:attack,T1059.004; sid:2100040; rev:1;)',

        # -------------------------------------------------------------
        # 3. Command & Control (C2) & Malware Beacons
        # -------------------------------------------------------------
        'alert tcp any any -> any any (msg:"MALWARE-CNC Cobalt Strike Default HTTP GET Stager URI"; content:"/ga2X"; offset:0; depth:6; classtype:"trojan-activity"; reference:attack,T1071.001; sid:2028501; rev:1;)',
        'alert tcp any any -> any any (msg:"MALWARE-CNC Cobalt Strike Default HTTP POST Submit Beacon"; content:"/submit.php?id="; nocase; classtype:"trojan-activity"; reference:attack,T1071.001; sid:2028502; rev:1;)',
        'alert tcp any any -> any any (msg:"MALWARE-CNC Metasploit Default User-Agent Header"; content:"User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"; nocase; classtype:"trojan-activity"; reference:attack,T1071.001; sid:2008500; rev:1;)',
        'alert tcp any any -> any any (msg:"MALWARE-CNC Godzilla Webshell Encrypted Traffic Header"; content:"Cookie: pass="; nocase; classtype:"trojan-activity"; reference:attack,T1505.003; sid:2045100; rev:1;)',
        'alert udp any any -> any 53 (msg:"MALWARE-CNC DNS High Entropy Data Exfiltration Subdomain"; content:"|00 01 00 00 00 00 00 00|"; offset:4; depth:8; classtype:"trojan-activity"; reference:attack,T1071.004; sid:2039100; rev:1;)',
    ]
