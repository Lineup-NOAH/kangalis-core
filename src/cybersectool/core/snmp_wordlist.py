"""SNMP topluluk-dizesi (community string) wordlist'i (IX-3).

Cihazlara karşı denenen yaygın/zayıf/varsayılan SNMP topluluk dizeleri. Bir cihaz
bunlardan biriyle okunabiliyorsa zayıf yapılandırma sayılır (onesixtyone / Metasploit
``snmp_login`` varsayılan listesinin küçük, küratörlü bir alt kümesi). Hepsi küçük
harf ve benzersizdir. Kullanıcının kimlik kasasından verdiği ÖZEL topluluk ayrıca
denenir ama "zayıf" sayılmaz (beklenen yapılandırma).
"""

from __future__ import annotations

SNMP_COMMUNITY_WORDLIST: tuple[str, ...] = (
    "public",
    "private",
    "manager",
    "agent",
    "admin",
    "snmp",
    "snmpd",
    "cisco",
    "ciscoworks",
    "system",
    "default",
    "community",
    "network",
    "monitor",
    "read",
    "write",
    "readonly",
    "readwrite",
    "access",
    "security",
    "secret",
    "router",
    "switch",
    "test",
    "guest",
    "password",
    "tivoli",
    "openview",
    "ilmi",
    "internal",
    "root",
    "enable",
)
