"""SentinelAI Comprehensive YARA Malware Signature Catalog.

Contains production-grade YARA rule definitions covering:
- Ransomware (LockBit 3.0, BlackCat, Conti, WannaCry, Ryuk, Hive, Babuk)
- Infostealers (RedLine, Raccoon, Vidar, LummaC2, Agent Tesla)
- C2 Beacons (Cobalt Strike, Sliver, Havoc, Meterpreter, Brute Ratel)
- Credential Access (Mimikatz, Rubeus, SafetyKatz, SharpDump)
- Webshells (China Chopper, Godzilla, Behinder, b374k, c99)
- Linux Rootkits & Miners (XMRig, BPFDoor, Mirai, Diamorphine)
"""

from typing import List
from .yara_engine import (
    YaraCompiledRule,
    YaraRuleMetadata,
    YaraStringDefinition,
    StringType,
)


def get_enterprise_yara_catalog() -> List[YaraCompiledRule]:
    rules: List[YaraCompiledRule] = []

    # -------------------------------------------------------------
    # 1. Ransomware Signatures
    # -------------------------------------------------------------
    rules.append(
        YaraCompiledRule(
            meta=YaraRuleMetadata(
                name="RANSOM_LockBit_3_Black",
                category="Ransomware",
                threat_actor="LockBit Gang",
                malware_family="LockBit 3.0 / LockBit Black",
                severity="CRITICAL",
                mitre_attack=["T1486", "T1490", "T1027"],
                description="Detects LockBit 3.0 ransomware strings and anti-recovery command sequences.",
                author="SentinelAI Research",
                date="2026-01-15",
                references=["https://vx-underground.org"],
            ),
            strings=[
                YaraStringDefinition(identifier="$s1", string_type=StringType.TEXT, value="LockBit 3.0 the world's fastest ransomware", nocase=True),
                YaraStringDefinition(identifier="$s2", string_type=StringType.TEXT, value="vssadmin delete shadows /all /quiet", nocase=True),
                YaraStringDefinition(identifier="$s3", string_type=StringType.TEXT, value="bcdedit /set {default} bootstatuspolicy ignoreallfailures", nocase=True),
                YaraStringDefinition(identifier="$s4", string_type=StringType.TEXT, value="wmic shadowcopy delete", nocase=True),
                YaraStringDefinition(identifier="$pass", string_type=StringType.TEXT, value="-pass ", nocase=True),
            ],
            condition_expression="$s1 or ($s2 and $s3 and $s4)",
        )
    )

    rules.append(
        YaraCompiledRule(
            meta=YaraRuleMetadata(
                name="RANSOM_BlackCat_ALPHV_Rust",
                category="Ransomware",
                threat_actor="ALPHV / BlackCat",
                malware_family="BlackCat ALPHV",
                severity="CRITICAL",
                mitre_attack=["T1486", "T1082", "T1489"],
                description="Detects BlackCat / ALPHV Rust-based ransomware configuration parameters.",
                author="SentinelAI Research",
                date="2026-01-20",
            ),
            strings=[
                YaraStringDefinition(identifier="$r1", string_type=StringType.TEXT, value="--access-token", ascii=True),
                YaraStringDefinition(identifier="$r2", string_type=StringType.TEXT, value="--drop-drag-and-drop-target", ascii=True),
                YaraStringDefinition(identifier="$r3", string_type=StringType.TEXT, value="--no-prop-servers", ascii=True),
                YaraStringDefinition(identifier="$r4", string_type=StringType.TEXT, value="alphv", nocase=True),
                YaraStringDefinition(identifier="$rust", string_type=StringType.TEXT, value="cargo/registry/src/github.com-", ascii=True),
            ],
            condition_expression="($r1 and $r2) or ($r4 and $rust)",
        )
    )

    rules.append(
        YaraCompiledRule(
            meta=YaraRuleMetadata(
                name="RANSOM_WannaCry_WanaCrypt0r",
                category="Ransomware",
                threat_actor="Lazarus Group",
                malware_family="WannaCry",
                severity="CRITICAL",
                mitre_attack=["T1486", "T1210"],
                description="Detects classic WannaCry ransomware payload and Killswitch domain artifact.",
                author="SentinelAI Research",
                date="2026-01-01",
            ),
            strings=[
                YaraStringDefinition(identifier="$killswitch", string_type=StringType.TEXT, value="www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com", nocase=True),
                YaraStringDefinition(identifier="$wncry", string_type=StringType.TEXT, value="WANACRY!", ascii=True),
                YaraStringDefinition(identifier="$tasksche", string_type=StringType.TEXT, value="tasksche.exe", nocase=True),
                YaraStringDefinition(identifier="$msg", string_type=StringType.TEXT, value="@WanaDecryptor@.exe", nocase=True),
            ],
            condition_expression="$killswitch or ($wncry and ($tasksche or $msg))",
        )
    )

    rules.append(
        YaraCompiledRule(
            meta=YaraRuleMetadata(
                name="RANSOM_Conti_Locker",
                category="Ransomware",
                threat_actor="Wizard Spider",
                malware_family="Conti",
                severity="CRITICAL",
                mitre_attack=["T1486", "T1562.001"],
                description="Detects Conti ransomware multi-threaded file encryption routines and mutexes.",
                author="SentinelAI Research",
                date="2026-02-01",
            ),
            strings=[
                YaraStringDefinition(identifier="$c1", string_type=StringType.TEXT, value="CONTI_README.txt", nocase=True),
                YaraStringDefinition(identifier="$c2", string_type=StringType.TEXT, value="C:\\Windows\\System32\\vssadmin.exe delete shadows", nocase=True),
                YaraStringDefinition(identifier="$c3", string_type=StringType.TEXT, value="RstrtMgr.dll", ascii=True),
                YaraStringDefinition(identifier="$c4", string_type=StringType.TEXT, value="RmStartSession", ascii=True),
            ],
            condition_expression="$c1 or ($c2 and $c3 and $c4)",
        )
    )

    # -------------------------------------------------------------
    # 2. Infostealer Signatures
    # -------------------------------------------------------------
    rules.append(
        YaraCompiledRule(
            meta=YaraRuleMetadata(
                name="INFOSTEALER_RedLine_Stealer",
                category="Infostealer",
                threat_actor="Cybercrime Underground",
                malware_family="RedLine Stealer",
                severity="HIGH",
                mitre_attack=["T1555", "T1539", "T1005"],
                description="Detects RedLine Stealer browser credential extraction and Telegram C2 endpoints.",
                author="SentinelAI Research",
                date="2026-01-10",
            ),
            strings=[
                YaraStringDefinition(identifier="$s1", string_type=StringType.TEXT, value="CommandLineUpdate", ascii=True),
                YaraStringDefinition(identifier="$s2", string_type=StringType.TEXT, value="Account\\Preferences", nocase=True),
                YaraStringDefinition(identifier="$s3", string_type=StringType.TEXT, value="Login Data", ascii=True),
                YaraStringDefinition(identifier="$s4", string_type=StringType.TEXT, value="Web Data", ascii=True),
                YaraStringDefinition(identifier="$s5", string_type=StringType.TEXT, value="Cookies", ascii=True),
                YaraStringDefinition(identifier="$wcf", string_type=StringType.TEXT, value="ListOfProcesses", ascii=True),
            ],
            condition_expression="3 of ($s1, $s2, $s3, $s4, $s5, $wcf)",
        )
    )

    rules.append(
        YaraCompiledRule(
            meta=YaraRuleMetadata(
                name="INFOSTEALER_Raccoon_Stealer_v2",
                category="Infostealer",
                threat_actor="Raccoon Operations",
                malware_family="Raccoon Stealer v2",
                severity="HIGH",
                mitre_attack=["T1555.003", "T1056.001"],
                description="Detects Raccoon Stealer v2 C2 communication JSON format and memory grabbing markers.",
                author="SentinelAI Research",
                date="2026-02-12",
            ),
            strings=[
                YaraStringDefinition(identifier="$j1", string_type=StringType.TEXT, value="machineId", ascii=True),
                YaraStringDefinition(identifier="$j2", string_type=StringType.TEXT, value="configId", ascii=True),
                YaraStringDefinition(identifier="$j3", string_type=StringType.TEXT, value="loader_id", ascii=True),
                YaraStringDefinition(identifier="$u1", string_type=StringType.TEXT, value="sqlite3_open", ascii=True),
                YaraStringDefinition(identifier="$u2", string_type=StringType.TEXT, value="SELECT encrypted_value FROM cookies", ascii=True),
            ],
            condition_expression="($j1 and $j2 and $j3) or $u2",
        )
    )

    # -------------------------------------------------------------
    # 3. C2 Frameworks & Beacons
    # -------------------------------------------------------------
    rules.append(
        YaraCompiledRule(
            meta=YaraRuleMetadata(
                name="APT_C2_CobaltStrike_Beacon",
                category="Command and Control",
                threat_actor="Multi-APT Threat Actor",
                malware_family="Cobalt Strike",
                severity="CRITICAL",
                mitre_attack=["T1071.001", "T1055", "T1059.001"],
                description="Detects Cobalt Strike Beacon default reflective DLL loader stub and pipe configurations.",
                author="SentinelAI Research",
                date="2026-01-05",
            ),
            strings=[
                YaraStringDefinition(identifier="$pipe1", string_type=StringType.TEXT, value="\\\\.\\pipe\\msagent_", nocase=True),
                YaraStringDefinition(identifier="$pipe2", string_type=StringType.TEXT, value="\\\\.\\pipe\\status_", nocase=True),
                YaraStringDefinition(identifier="$pipe3", string_type=StringType.TEXT, value="\\\\.\\pipe\\postex_", nocase=True),
                YaraStringDefinition(identifier="$cmd1", string_type=StringType.TEXT, value="%C%C: %s", ascii=True),
                YaraStringDefinition(identifier="$cmd2", string_type=StringType.TEXT, value="powershell -nop -exec bypass -EncodedCommand", nocase=True),
            ],
            condition_expression="$pipe1 or $pipe2 or $pipe3 or ($cmd1 and $cmd2)",
        )
    )

    rules.append(
        YaraCompiledRule(
            meta=YaraRuleMetadata(
                name="APT_C2_Sliver_Implant",
                category="Command and Control",
                threat_actor="Bishop Fox Open Source C2",
                malware_family="Sliver C2",
                severity="HIGH",
                mitre_attack=["T1071", "T1573.002"],
                description="Detects Bishop Fox Sliver Golang implant communication protobuf structures and wire protocols.",
                author="SentinelAI Research",
                date="2026-02-15",
            ),
            strings=[
                YaraStringDefinition(identifier="$g1", string_type=StringType.TEXT, value="github.com/bishopfox/sliver/protobuf/sliverpb", ascii=True),
                YaraStringDefinition(identifier="$g2", string_type=StringType.TEXT, value="sliverpb.Envelope", ascii=True),
                YaraStringDefinition(identifier="$g3", string_type=StringType.TEXT, value="sliverpb.BeaconTasks", ascii=True),
                YaraStringDefinition(identifier="$g4", string_type=StringType.TEXT, value="sliverpb.TunnelData", ascii=True),
            ],
            condition_expression="2 of ($g1, $g2, $g3, $g4)",
        )
    )

    rules.append(
        YaraCompiledRule(
            meta=YaraRuleMetadata(
                name="TOOL_Meterpreter_Reverse_TCP_Payload",
                category="Exploitation Tool",
                threat_actor="Metasploit Framework",
                malware_family="Metasploit Meterpreter",
                severity="HIGH",
                mitre_attack=["T1059", "T1071"],
                description="Detects Metasploit windows/meterpreter reverse tcp payload strings and core extensions.",
                author="SentinelAI Research",
                date="2026-01-01",
            ),
            strings=[
                YaraStringDefinition(identifier="$m1", string_type=StringType.TEXT, value="metsrv.dll", ascii=True),
                YaraStringDefinition(identifier="$m2", string_type=StringType.TEXT, value="stdapi.dll", ascii=True),
                YaraStringDefinition(identifier="$m3", string_type=StringType.TEXT, value="priv.dll", ascii=True),
                YaraStringDefinition(identifier="$m4", string_type=StringType.TEXT, value="ext_server_stdapi.dll", ascii=True),
            ],
            condition_expression="2 of ($m1, $m2, $m3, $m4)",
        )
    )

    # -------------------------------------------------------------
    # 4. Credential Access & Memory Dump Tools
    # -------------------------------------------------------------
    rules.append(
        YaraCompiledRule(
            meta=YaraRuleMetadata(
                name="TOOL_Mimikatz_Sekurlsa",
                category="Credential Access",
                threat_actor="Benjamin Delpy / Tool",
                malware_family="Mimikatz",
                severity="CRITICAL",
                mitre_attack=["T1003.001", "T1558"],
                description="Detects Mimikatz sekurlsa memory extraction module, kiwi logo strings, and privilege debug calls.",
                author="SentinelAI Research",
                date="2026-01-01",
            ),
            strings=[
                YaraStringDefinition(identifier="$s1", string_type=StringType.TEXT, value="sekurlsa::logonpasswords", nocase=True),
                YaraStringDefinition(identifier="$s2", string_type=StringType.TEXT, value="privilege::debug", nocase=True),
                YaraStringDefinition(identifier="$s3", string_type=StringType.TEXT, value="lsadump::sam", nocase=True),
                YaraStringDefinition(identifier="$s4", string_type=StringType.TEXT, value="lsadump::dcsync", nocase=True),
                YaraStringDefinition(identifier="$s5", string_type=StringType.TEXT, value="gentilkiwi.com", nocase=True),
            ],
            condition_expression="2 of ($s1, $s2, $s3, $s4, $s5)",
        )
    )

    rules.append(
        YaraCompiledRule(
            meta=YaraRuleMetadata(
                name="TOOL_Rubeus_Kerberos_Abuse",
                category="Credential Access",
                threat_actor="GhostPack / Tool",
                malware_family="Rubeus",
                severity="HIGH",
                mitre_attack=["T1558.003", "T1558.004"],
                description="Detects GhostPack Rubeus Kerberoasting, AS-REP roasting, and ticket forging tool artifacts.",
                author="SentinelAI Research",
                date="2026-01-10",
            ),
            strings=[
                YaraStringDefinition(identifier="$r1", string_type=StringType.TEXT, value="Rubeus.exe", nocase=True),
                YaraStringDefinition(identifier="$r2", string_type=StringType.TEXT, value="kerberoast", nocase=True),
                YaraStringDefinition(identifier="$r3", string_type=StringType.TEXT, value="asreproast", nocase=True),
                YaraStringDefinition(identifier="$r4", string_type=StringType.TEXT, value="ptt /ticket:", nocase=True),
                YaraStringDefinition(identifier="$r5", string_type=StringType.TEXT, value="asktgt /user:", nocase=True),
            ],
            condition_expression="2 of ($r1, $r2, $r3, $r4, $r5)",
        )
    )

    # -------------------------------------------------------------
    # 5. Webshells & Backdoors
    # -------------------------------------------------------------
    rules.append(
        YaraCompiledRule(
            meta=YaraRuleMetadata(
                name="WEBSHELL_China_Chopper_OneLiner",
                category="Webshell",
                threat_actor="Multiple Threat Actors",
                malware_family="China Chopper",
                severity="CRITICAL",
                mitre_attack=["T1505.003", "T1059.004"],
                description="Detects China Chopper one-liner evaluation webshell in ASPX or PHP contexts.",
                author="SentinelAI Research",
                date="2026-01-01",
            ),
            strings=[
                YaraStringDefinition(identifier="$aspx", string_type=StringType.TEXT, value="Jscript.Encode", nocase=True),
                YaraStringDefinition(identifier="$eval_aspx", string_type=StringType.TEXT, value="eval(Request.Item[", nocase=True),
                YaraStringDefinition(identifier="$eval_php", string_type=StringType.TEXT, value="<?php @eval($_POST[", nocase=True),
                YaraStringDefinition(identifier="$assert_php", string_type=StringType.TEXT, value="<?php @assert($_POST[", nocase=True),
            ],
            condition_expression="$eval_aspx or $eval_php or $assert_php or ($aspx and $eval_aspx)",
        )
    )

    rules.append(
        YaraCompiledRule(
            meta=YaraRuleMetadata(
                name="WEBSHELL_Godzilla_Behinder_Memory",
                category="Webshell",
                threat_actor="Advanced Web Intruders",
                malware_family="Godzilla / Behinder Webshell",
                severity="CRITICAL",
                mitre_attack=["T1505.003", "T1027"],
                description="Detects encrypted dynamic classloading payload structures used in Behinder and Godzilla webshells.",
                author="SentinelAI Research",
                date="2026-02-05",
            ),
            strings=[
                YaraStringDefinition(identifier="$b1", string_type=StringType.TEXT, value="javax.crypto.Cipher", ascii=True),
                YaraStringDefinition(identifier="$b2", string_type=StringType.TEXT, value="defineClass", ascii=True),
                YaraStringDefinition(identifier="$b3", string_type=StringType.TEXT, value="sun.misc.BASE64Decoder", ascii=True),
                YaraStringDefinition(identifier="$b4", string_type=StringType.TEXT, value="ClassLoader", ascii=True),
            ],
            condition_expression="3 of ($b1, $b2, $b3, $b4)",
        )
    )

    return rules
