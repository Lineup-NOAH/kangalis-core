"""Kimlik kasası: şifreleme + Credential / CredentialZone CRUD testleri."""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cybersectool.core.credentials import (
    create_credential,
    create_credential_zone,
    credentials_in_zone,
    default_port,
    delete_credential,
    effective_port,
    get_secret,
    list_credentials,
    update_credential,
    update_credential_zone,
)
from cybersectool.core.crypto import decrypt_secret, encrypt_secret
from cybersectool.core.models import CredentialType


def test_encrypt_decrypt_roundtrip() -> None:
    token = encrypt_secret("Sup3rGizli!")
    assert token != "Sup3rGizli!"  # şifreli, düz metin değil
    assert decrypt_secret(token) == "Sup3rGizli!"
    # Aynı metin farklı token üretir (Fernet rastgele IV), ikisi de çözülür.
    assert encrypt_secret("x") != encrypt_secret("x")


def test_default_ports() -> None:
    assert default_port(CredentialType.ssh) == 22
    assert default_port(CredentialType.winrm) == 5985
    assert default_port(CredentialType.rdp) == 3389


async def test_create_credential_encrypts(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as session:
        cred = await create_credential(
            session, "linux-root", CredentialType.ssh, "root", "parola123", description="prod"
        )
        # Parola DB'de düz metin DEĞİL, şifreli.
        assert cred.secret_encrypted != "parola123"
        assert get_secret(cred) == "parola123"
        assert effective_port(cred) == 22  # tip varsayılanı

        cred2 = await create_credential(
            session, "win-admin", CredentialType.winrm, "Administrator", "P@ss", port=5986
        )
        assert effective_port(cred2) == 5986  # özel port tipin varsayılanını ezer


async def test_update_credential_keeps_password_when_blank(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as session:
        cred = await create_credential(
            session, "linux-root", CredentialType.ssh, "root", "ilkparola"
        )
        # Parola boş → değişmez; kullanıcı adı + port güncellenir.
        upd = await update_credential(
            session, cred.id, "linux-root2", CredentialType.ssh, "admin", secret=None, port=2222
        )
        assert upd is not None
        assert upd.name == "linux-root2"
        assert upd.username == "admin"
        assert upd.port == 2222
        assert get_secret(upd) == "ilkparola"  # parola korundu
        # Yeni parola verilince değişir.
        upd2 = await update_credential(
            session, cred.id, "linux-root2", CredentialType.ssh, "admin", secret="yeniparola"
        )
        assert upd2 is not None
        assert get_secret(upd2) == "yeniparola"
        # Olmayan kimlik → None.
        assert await update_credential(session, 9999, "x", CredentialType.ssh, "u") is None


async def test_update_credential_zone(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as session:
        c1 = await create_credential(session, "c1", CredentialType.ssh, "u1", "p1")
        c2 = await create_credential(session, "c2", CredentialType.ssh, "u2", "p2")
        zone = await create_credential_zone(session, "zg", [c1.id])
        # Bölgeye c2 eklenir, c1 çıkarılır.
        upd = await update_credential_zone(session, zone.id, "zg-2", [c2.id], "desc")
        assert upd is not None
        assert upd.name == "zg-2"
        assert upd.credential_ids == [c2.id]
        members = await credentials_in_zone(session, upd)
        assert [m.id for m in members] == [c2.id]
        # Hiç geçerli kimlik kalmazsa ValueError.
        with pytest.raises(ValueError):
            await update_credential_zone(session, zone.id, "zg-2", [9999])
        # Olmayan bölge → None.
        assert await update_credential_zone(session, 9999, "x", [c1.id]) is None


async def test_create_credential_validation(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as session:
        await create_credential(session, "dup", CredentialType.ssh, "u", "p")
        with pytest.raises(ValueError):  # aynı isim
            await create_credential(session, "dup", CredentialType.ssh, "u", "p")
        with pytest.raises(ValueError):  # boş parola
            await create_credential(session, "bos", CredentialType.ssh, "u", "")


async def test_delete_credential(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as session:
        cred = await create_credential(session, "geçici", CredentialType.ssh, "u", "p")
        assert await delete_credential(session, cred.id) is True
        assert await delete_credential(session, cred.id) is False
        assert await list_credentials(session) == []


async def test_credential_zone(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as session:
        c1 = await create_credential(session, "c1", CredentialType.ssh, "u", "p")
        c2 = await create_credential(session, "c2", CredentialType.winrm, "a", "p")

        zone = await create_credential_zone(
            session,
            "karma",
            [c1.id, c2.id, 9999],
            "test",  # 9999 yok → elenir
        )
        assert zone.credential_ids == [c1.id, c2.id]

        members = await credentials_in_zone(session, zone)
        assert [m.name for m in members] == ["c1", "c2"]

        with pytest.raises(ValueError):  # hiç geçerli id yok
            await create_credential_zone(session, "bos", [9999])
        with pytest.raises(ValueError):  # aynı isim
            await create_credential_zone(session, "karma", [c1.id])
