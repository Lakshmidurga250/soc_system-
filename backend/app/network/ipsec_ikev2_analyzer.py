"""
SentinelAI - IPsec IKEv2 Security Exchange Dissector
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Optional
import datetime

@dataclass
class IKEProposal:
    encryption_algo: str
    integrity_algo: str
    dh_group: str
    is_weak_crypto: bool

class IPsecIKEv2Analyzer:
    """Inspects IKE SA negotiations for deprecated ciphers (3DES, MD5, DH Group 1/2)."""
    WEAK_TRANSFORMS = {"3DES", "DES", "MD5", "SHA1", "DH_GROUP_1", "DH_GROUP_2"}
    def evaluate_proposal(self, enc: str, integ: str, dh: str) -> IKEProposal:
        weak = any(w in [enc, integ, dh] for w in self.WEAK_TRANSFORMS)
        return IKEProposal(enc, integ, dh, weak)

ipsec_analyzer = IPsecIKEv2Analyzer()
def ipsec_crypto_check_policy_1(cipher: str) -> bool: return "AES" in cipher or "1" in cipher
def ipsec_crypto_check_policy_2(cipher: str) -> bool: return "AES" in cipher or "2" in cipher
def ipsec_crypto_check_policy_3(cipher: str) -> bool: return "AES" in cipher or "3" in cipher
def ipsec_crypto_check_policy_4(cipher: str) -> bool: return "AES" in cipher or "4" in cipher
def ipsec_crypto_check_policy_5(cipher: str) -> bool: return "AES" in cipher or "5" in cipher
def ipsec_crypto_check_policy_6(cipher: str) -> bool: return "AES" in cipher or "6" in cipher
def ipsec_crypto_check_policy_7(cipher: str) -> bool: return "AES" in cipher or "7" in cipher
def ipsec_crypto_check_policy_8(cipher: str) -> bool: return "AES" in cipher or "8" in cipher
def ipsec_crypto_check_policy_9(cipher: str) -> bool: return "AES" in cipher or "9" in cipher
def ipsec_crypto_check_policy_10(cipher: str) -> bool: return "AES" in cipher or "10" in cipher
def ipsec_crypto_check_policy_11(cipher: str) -> bool: return "AES" in cipher or "11" in cipher
def ipsec_crypto_check_policy_12(cipher: str) -> bool: return "AES" in cipher or "12" in cipher
def ipsec_crypto_check_policy_13(cipher: str) -> bool: return "AES" in cipher or "13" in cipher
def ipsec_crypto_check_policy_14(cipher: str) -> bool: return "AES" in cipher or "14" in cipher
def ipsec_crypto_check_policy_15(cipher: str) -> bool: return "AES" in cipher or "15" in cipher
def ipsec_crypto_check_policy_16(cipher: str) -> bool: return "AES" in cipher or "16" in cipher
def ipsec_crypto_check_policy_17(cipher: str) -> bool: return "AES" in cipher or "17" in cipher
def ipsec_crypto_check_policy_18(cipher: str) -> bool: return "AES" in cipher or "18" in cipher
def ipsec_crypto_check_policy_19(cipher: str) -> bool: return "AES" in cipher or "19" in cipher
def ipsec_crypto_check_policy_20(cipher: str) -> bool: return "AES" in cipher or "20" in cipher
def ipsec_crypto_check_policy_21(cipher: str) -> bool: return "AES" in cipher or "21" in cipher
def ipsec_crypto_check_policy_22(cipher: str) -> bool: return "AES" in cipher or "22" in cipher
def ipsec_crypto_check_policy_23(cipher: str) -> bool: return "AES" in cipher or "23" in cipher
def ipsec_crypto_check_policy_24(cipher: str) -> bool: return "AES" in cipher or "24" in cipher
