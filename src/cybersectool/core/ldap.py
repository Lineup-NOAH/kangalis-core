"""LDAP / Active Directory ile kimlik doğrulama (opsiyonel).

Basit *bind* doğrulaması: kullanıcı adı + parola ile LDAP sunucusuna bağlanılır;
bağlanma başarılıysa kimlik doğrulanmış sayılır. Parola/dizin **uygulamada
saklanmaz**. ``ldap3`` yalnızca bind sırasında (lazy) import edilir; bu modülü
import etmek LDAP sunucusu/paketi olmayan ortamlarda da güvenlidir.

GÜVENLİK: boş parola ile "unauthenticated bind" birçok sunucuda doğrulamasız
başarılı olur — bu yüzden boş parola/kullanıcı açıkça reddedilir. Kullanıcı adı
DN/UPN'e gömüldüğü için enjeksiyon riskli karakterler de reddedilir.

LDAPS (use_ssl) bağlantılarında, ``verify_cert`` açıkken sunucu sertifikası
doğrulanır (``ldap3.Tls(validate=CERT_REQUIRED)``) — aksi halde MITM ile servis
hesabı/kullanıcı parolası çalınabilir. ``ca_cert`` (PEM) verilirse o CA ile, yoksa
sistem güven deposu ile doğrulanır. Varsayılan kapalı (geriye uyum korunur).
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from cybersectool.config import settings

if TYPE_CHECKING:
    from cybersectool.core.models import LdapConfig

# Bind DN/UPN içine güvenle gömülebilecek kullanıcı adı karakterleri.
_VALID_USERNAME = re.compile(r"^[A-Za-z0-9._@\-]+$")


def valid_ldap_username(username: str) -> bool:
    """Kullanıcı adı DN/UPN enjeksiyonuna karşı güvenli mi (1–64 izinli karakter)?"""
    return bool(username) and len(username) <= 64 and _VALID_USERNAME.match(username) is not None


def _make_server(
    uri: str, use_ssl: bool, *, verify_cert: bool = False, ca_cert: str | None = None
) -> object:
    """ldap3.Server kurar. LDAPS + verify_cert açıkken sertifika doğrulaması zorunlu olur.

    ca_cert (PEM) verilirse o CA ile, yoksa sistem güven deposu ile doğrulanır.
    verify_cert kapalıyken (varsayılan) eski davranış korunur (doğrulama yok).
    """
    import ldap3

    tls = None
    if use_ssl and verify_cert:
        import ssl

        ca_data = ca_cert.strip() if ca_cert and ca_cert.strip() else None
        tls = ldap3.Tls(validate=ssl.CERT_REQUIRED, ca_certs_data=ca_data)
    return ldap3.Server(uri, use_ssl=use_ssl, get_info=ldap3.NONE, connect_timeout=5, tls=tls)


def _bind(username: str, password: str, verify_cert: bool, ca_cert: str | None) -> bool:
    """Senkron LDAP bind denemesi (asyncio.to_thread ile çağrılır)."""
    import ldap3

    bind_dn = settings.ldap_bind_dn_template.format(username=username)
    try:
        server = _make_server(
            settings.ldap_server_uri,
            settings.ldap_use_ssl,
            verify_cert=verify_cert,
            ca_cert=ca_cert,
        )
        conn = ldap3.Connection(server, user=bind_dn, password=password)
        if not conn.bind():
            return False
        conn.unbind()
        return True
    except Exception:
        # Sunucuya ulaşılamadı / TLS hatası / kötü DN vb. → doğrulanmadı.
        return False


async def ldap_authenticate(
    username: str, password: str, *, verify_cert: bool = False, ca_cert: str | None = None
) -> bool:
    """LDAP bind ile kullanıcıyı doğrular. Başarılıysa True.

    Boş parola/kullanıcı ya da geçersiz kullanıcı adı anında reddedilir (ağ yok).
    LDAP kapalıysa ya da sunucu tanımsızsa False döner. LDAPS'te verify_cert açıksa
    sunucu sertifikası doğrulanır.
    """
    if not settings.ldap_enabled or not settings.ldap_server_uri:
        return False
    if not password or not valid_ldap_username(username):
        return False
    return await asyncio.to_thread(_bind, username, password, verify_cert, ca_cert)


# --- LDAP kullanıcı arama / içe aktarma (DB yapılandırmasıyla) ---


@dataclass
class LdapUser:
    """LDAP dizininden okunan bir kullanıcı (içe aktarmadan önce)."""

    username: str
    email: str | None
    display_name: str | None
    dn: str


def _search_users(
    config: LdapConfig, bind_password: str, query: str, verify_cert: bool, ca_cert: str | None
) -> list[LdapUser]:
    """Senkron LDAP kullanıcı araması (asyncio.to_thread ile çağrılır)."""
    import ldap3
    from ldap3.utils.conv import escape_filter_chars

    try:
        server = _make_server(
            config.server_uri, config.use_ssl, verify_cert=verify_cert, ca_cert=ca_cert
        )
        # Bind DN boşsa anonim bind denenir.
        conn = ldap3.Connection(
            server, user=config.bind_dn or None, password=bind_password or None, read_only=True
        )
        if not conn.bind():
            raise LdapSearchError("LDAP bind başarısız (servis hesabı DN/parola).")
    except LdapSearchError:
        raise
    except Exception as exc:  # sunucuya ulaşılamadı / DNS / TLS vb.
        raise LdapSearchError(f"LDAP bağlantı hatası: {exc}") from exc
    try:
        base_filter = config.user_filter or "(objectClass=person)"
        if query.strip():
            q = escape_filter_chars(query.strip())
            search_filter = (
                f"(&{base_filter}(|({config.attr_username}=*{q}*)"
                f"({config.attr_display_name}=*{q}*)))"
            )
        else:
            search_filter = base_filter
        conn.search(
            config.base_dn,
            search_filter,
            search_scope=ldap3.SUBTREE,
            attributes=[config.attr_username, config.attr_email, config.attr_display_name],
            size_limit=200,
        )
        users: list[LdapUser] = []
        for entry in conn.entries:
            uname = _attr_value(entry, config.attr_username)
            if not uname:
                continue
            users.append(
                LdapUser(
                    username=uname,
                    email=_attr_value(entry, config.attr_email),
                    display_name=_attr_value(entry, config.attr_display_name),
                    dn=str(entry.entry_dn),
                )
            )
        return users
    finally:
        conn.unbind()


def _attr_value(entry: object, attr: str) -> str | None:
    """ldap3 girdisinden bir özniteliğin ilk değerini güvenle okur."""
    try:
        value = entry[attr].value  # type: ignore[index]
    except Exception:
        return None
    if value is None:
        return None
    if isinstance(value, list):
        return str(value[0]) if value else None
    return str(value)


class LdapSearchError(Exception):
    """LDAP arama/test sırasında bağlantı veya bind hatası."""


async def ldap_search_users(
    config: LdapConfig,
    bind_password: str,
    query: str = "",
    *,
    verify_cert: bool = False,
    ca_cert: str | None = None,
) -> list[LdapUser]:
    """LDAP dizininde kullanıcı arar (yapılandırma + bind parolası ile)."""
    if not config.server_uri or not config.base_dn:
        raise LdapSearchError("Sunucu adresi ve arama tabanı (base DN) gerekli.")
    return await asyncio.to_thread(
        _search_users, config, bind_password, query, verify_cert, ca_cert
    )


def _test_connection(
    config: LdapConfig, bind_password: str, verify_cert: bool, ca_cert: str | None
) -> tuple[bool, str]:
    """Senkron bağlantı/bind testi."""
    import ldap3

    try:
        server = _make_server(
            config.server_uri, config.use_ssl, verify_cert=verify_cert, ca_cert=ca_cert
        )
        conn = ldap3.Connection(server, user=config.bind_dn or None, password=bind_password or None)
        if not conn.bind():
            return False, "Bind başarısız — sunucu/DN/parolayı kontrol edin."
        conn.unbind()
        return True, "Bağlantı ve bind başarılı."
    except Exception as exc:  # noqa: BLE001
        return False, f"Bağlantı hatası: {exc}"


async def ldap_test_connection(
    config: LdapConfig,
    bind_password: str,
    *,
    verify_cert: bool = False,
    ca_cert: str | None = None,
) -> tuple[bool, str]:
    """LDAP sunucusuna bağlanıp bind dener; (başarılı?, mesaj) döndürür."""
    if not config.server_uri:
        return False, "Sunucu adresi (URI) gerekli."
    return await asyncio.to_thread(_test_connection, config, bind_password, verify_cert, ca_cert)


# --- OU / güvenlik grubu / grup üyesi çekme (OpenLDAP + AD otomatik algılanır) ---

# OpenLDAP (groupOfNames/groupOfUniqueNames/posixGroup) + Active Directory (group).
_GROUP_FILTER = (
    "(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)"
    "(objectClass=posixGroup)(objectClass=group))"
)
# Üye listesi öznitelikleri: member/uniqueMember = DN listesi, memberUid = kullanıcı adı.
_MEMBER_ATTRS = ("member", "uniqueMember", "memberUid")


@dataclass
class LdapGroup:
    """LDAP güvenlik grubu / OU (içe aktarma öncesi)."""

    dn: str
    name: str
    member_count: int


def _connect(
    config: LdapConfig, bind_password: str, verify_cert: bool, ca_cert: str | None
) -> object:
    """Servis hesabıyla salt-okunur bağlanır; hata → LdapSearchError."""
    import ldap3

    try:
        server = _make_server(
            config.server_uri, config.use_ssl, verify_cert=verify_cert, ca_cert=ca_cert
        )
        conn = ldap3.Connection(
            server, user=config.bind_dn or None, password=bind_password or None, read_only=True
        )
        if not conn.bind():
            raise LdapSearchError("LDAP bind başarısız (servis hesabı DN/parola).")
        return conn
    except LdapSearchError:
        raise
    except Exception as exc:  # sunucuya ulaşılamadı / DNS / TLS vb.
        raise LdapSearchError(f"LDAP bağlantı hatası: {exc}") from exc


def _entry_values(entry: object, attr: str) -> list[str]:
    """ldap3 girdisinden bir özniteliğin tüm değerlerini güvenle okur."""
    try:
        values = entry[attr].values  # type: ignore[index]
    except Exception:
        return []
    return [str(v) for v in values] if values else []


def _list_ous(
    config: LdapConfig, bind_password: str, verify_cert: bool, ca_cert: str | None
) -> list[LdapGroup]:
    import ldap3

    conn = _connect(config, bind_password, verify_cert, ca_cert)
    try:
        conn.search(  # type: ignore[attr-defined]
            config.base_dn,
            "(objectClass=organizationalUnit)",
            search_scope=ldap3.SUBTREE,
            attributes=["ou", "name"],
            size_limit=200,
        )
        ous: list[LdapGroup] = []
        for entry in conn.entries:  # type: ignore[attr-defined]
            name = _attr_value(entry, "ou") or _attr_value(entry, "name") or str(entry.entry_dn)
            ous.append(LdapGroup(dn=str(entry.entry_dn), name=name, member_count=0))
        return ous
    finally:
        conn.unbind()  # type: ignore[attr-defined]


def _list_groups(
    config: LdapConfig, bind_password: str, verify_cert: bool, ca_cert: str | None
) -> list[LdapGroup]:
    import ldap3

    conn = _connect(config, bind_password, verify_cert, ca_cert)
    try:
        conn.search(  # type: ignore[attr-defined]
            config.base_dn,
            _GROUP_FILTER,
            search_scope=ldap3.SUBTREE,
            attributes=["cn", "name", *_MEMBER_ATTRS],
            size_limit=300,
        )
        groups: list[LdapGroup] = []
        for entry in conn.entries:  # type: ignore[attr-defined]
            name = _attr_value(entry, "cn") or _attr_value(entry, "name") or str(entry.entry_dn)
            count = 0
            for attr in _MEMBER_ATTRS:
                count = max(count, len(_entry_values(entry, attr)))
            groups.append(LdapGroup(dn=str(entry.entry_dn), name=name, member_count=count))
        return groups
    finally:
        conn.unbind()  # type: ignore[attr-defined]


def _group_members(
    config: LdapConfig,
    bind_password: str,
    group_dn: str,
    verify_cert: bool,
    ca_cert: str | None,
) -> list[LdapUser]:
    import ldap3

    conn = _connect(config, bind_password, verify_cert, ca_cert)
    try:
        conn.search(  # type: ignore[attr-defined]
            group_dn,
            _GROUP_FILTER,
            search_scope=ldap3.BASE,
            attributes=list(_MEMBER_ATTRS),
        )
        entries = list(conn.entries)  # type: ignore[attr-defined]
        if not entries:
            return []
        group = entries[0]
        # memberUid (posixGroup) → değerler doğrudan kullanıcı adı.
        uids = _entry_values(group, "memberUid")
        if uids:
            return [LdapUser(username=u, email=None, display_name=None, dn="") for u in uids[:500]]
        # member / uniqueMember → DN listesi; her DN'i çözüp kullanıcı adını oku.
        dns = _entry_values(group, "member") or _entry_values(group, "uniqueMember")
        members: list[LdapUser] = []
        for member_dn in dns[:500]:
            try:
                conn.search(  # type: ignore[attr-defined]
                    member_dn,
                    "(objectClass=*)",
                    search_scope=ldap3.BASE,
                    attributes=[
                        config.attr_username,
                        config.attr_email,
                        config.attr_display_name,
                    ],
                )
                sub = list(conn.entries)  # type: ignore[attr-defined]
            except Exception:
                continue
            if not sub:
                continue
            uname = _attr_value(sub[0], config.attr_username)
            if not uname:
                continue
            members.append(
                LdapUser(
                    username=uname,
                    email=_attr_value(sub[0], config.attr_email),
                    display_name=_attr_value(sub[0], config.attr_display_name),
                    dn=member_dn,
                )
            )
        return members
    finally:
        conn.unbind()  # type: ignore[attr-defined]


async def ldap_list_ous(
    config: LdapConfig,
    bind_password: str,
    *,
    verify_cert: bool = False,
    ca_cert: str | None = None,
) -> list[LdapGroup]:
    """Dizindeki organizasyon birimlerini (OU) listeler."""
    if not config.server_uri or not config.base_dn:
        raise LdapSearchError("Sunucu adresi ve arama tabanı (base DN) gerekli.")
    return await asyncio.to_thread(_list_ous, config, bind_password, verify_cert, ca_cert)


async def ldap_list_groups(
    config: LdapConfig,
    bind_password: str,
    *,
    verify_cert: bool = False,
    ca_cert: str | None = None,
) -> list[LdapGroup]:
    """Dizindeki güvenlik gruplarını listeler (OpenLDAP + AD)."""
    if not config.server_uri or not config.base_dn:
        raise LdapSearchError("Sunucu adresi ve arama tabanı (base DN) gerekli.")
    return await asyncio.to_thread(_list_groups, config, bind_password, verify_cert, ca_cert)


async def ldap_group_members(
    config: LdapConfig,
    bind_password: str,
    group_dn: str,
    *,
    verify_cert: bool = False,
    ca_cert: str | None = None,
) -> list[LdapUser]:
    """Bir grubun üyelerini (kullanıcı olarak) döndürür."""
    if not config.server_uri:
        raise LdapSearchError("Sunucu adresi (URI) gerekli.")
    return await asyncio.to_thread(
        _group_members, config, bind_password, group_dn, verify_cert, ca_cert
    )
