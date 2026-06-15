"""Kimlik kasası servis fonksiyonları: Credential + CredentialZone CRUD.

Parolalar `core.crypto` ile **şifreli** saklanır; düz metin yalnızca tarama anında
`get_secret` ile çözülür. Kimlik bölgeleri (CredentialZone) bir Credential id grubudur —
IP zone'unun kimlik karşılığı.
"""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from cybersectool.core.crypto import decrypt_secret, encrypt_secret
from cybersectool.core.models import Credential, CredentialType, CredentialZone

# Tip başına varsayılan bağlantı portu.
DEFAULT_PORTS: dict[CredentialType, int] = {
    CredentialType.ssh: 22,
    CredentialType.winrm: 5985,
    CredentialType.rdp: 3389,
    CredentialType.postgres: 5432,
    CredentialType.mysql: 3306,
    CredentialType.mssql: 1433,
    CredentialType.oracle: 1521,
    CredentialType.snmp: 161,
    CredentialType.smb: 445,
    CredentialType.ldap: 389,
    CredentialType.telnet: 23,
}


def default_port(cred_type: CredentialType) -> int:
    return DEFAULT_PORTS.get(cred_type, 22)


def effective_port(credential: Credential) -> int:
    """Kimlik için kullanılacak port: özel port verilmişse o, yoksa tipin varsayılanı."""
    return credential.port or default_port(credential.cred_type)


def get_secret(credential: Credential) -> str:
    """Saklanan şifreli parolayı çözer (yalnızca bağlantı anında çağrılmalı)."""
    return decrypt_secret(credential.secret_encrypted)


# --- Credential CRUD ---


async def create_credential(
    session: AsyncSession,
    name: str,
    cred_type: CredentialType,
    username: str,
    secret: str,
    *,
    domain: str | None = None,
    port: int | None = None,
    description: str | None = None,
) -> Credential:
    if not secret:
        raise ValueError("Parola boş olamaz.")
    existing = await session.execute(select(Credential).where(Credential.name == name))
    if existing.scalars().first() is not None:
        raise ValueError(f"'{name}' adında bir kimlik zaten var.")
    credential = Credential(
        name=name,
        cred_type=cred_type,
        username=username,
        secret_encrypted=encrypt_secret(secret),
        domain=domain,
        port=port,
        description=description,
    )
    session.add(credential)
    await session.commit()
    await session.refresh(credential)
    return credential


async def list_credentials(session: AsyncSession) -> list[Credential]:
    result = await session.execute(select(Credential).order_by(Credential.id.desc()))
    return list(result.scalars().all())


async def get_credential(session: AsyncSession, credential_id: int) -> Credential | None:
    return await session.get(Credential, credential_id)


async def update_credential(
    session: AsyncSession,
    credential_id: int,
    name: str,
    cred_type: CredentialType,
    username: str,
    *,
    secret: str | None = None,
    domain: str | None = None,
    port: int | None = None,
    description: str | None = None,
) -> Credential | None:
    """Kimliği günceller. ``secret`` boş/None ise mevcut parola korunur (yeniden gösterilmez)."""
    credential = await session.get(Credential, credential_id)
    if credential is None:
        return None
    if name != credential.name:
        clash = await session.execute(
            select(Credential).where(Credential.name == name, Credential.id != credential_id)
        )
        if clash.scalars().first() is not None:
            raise ValueError(f"'{name}' adında bir kimlik zaten var.")
    credential.name = name
    credential.cred_type = cred_type
    credential.username = username
    if secret:  # boş bırakılırsa parola değişmez
        credential.secret_encrypted = encrypt_secret(secret)
    credential.domain = domain
    credential.port = port
    credential.description = description
    await session.commit()
    await session.refresh(credential)
    return credential


async def delete_credential(session: AsyncSession, credential_id: int) -> bool:
    credential = await session.get(Credential, credential_id)
    if credential is None:
        return False
    await session.delete(credential)
    await session.commit()
    return True


async def count_credentials(session: AsyncSession) -> int:
    result = await session.execute(select(func.count()).select_from(Credential))
    return int(result.scalar_one() or 0)


# --- CredentialZone CRUD ---


async def create_credential_zone(
    session: AsyncSession,
    name: str,
    credential_ids: list[int],
    description: str | None = None,
) -> CredentialZone:
    """Kimlik bölgesi oluşturur. Var olmayan id'ler sessizce elenir; hiç kalmazsa ValueError."""
    existing = await session.execute(select(CredentialZone).where(CredentialZone.name == name))
    if existing.scalars().first() is not None:
        raise ValueError(f"'{name}' adında bir kimlik bölgesi zaten var.")
    valid_ids = await _existing_credential_ids(session, credential_ids)
    if not valid_ids:
        raise ValueError("En az bir geçerli kimlik seçilmeli.")
    zone = CredentialZone(name=name, credential_ids=valid_ids, description=description)
    session.add(zone)
    await session.commit()
    await session.refresh(zone)
    return zone


async def _existing_credential_ids(session: AsyncSession, ids: list[int]) -> list[int]:
    if not ids:
        return []
    result = await session.execute(select(Credential.id).where(Credential.id.in_(ids)))
    found = set(result.scalars().all())
    # Girdi sırasını koru.
    return [i for i in ids if i in found]


async def list_credential_zones(session: AsyncSession) -> list[CredentialZone]:
    result = await session.execute(select(CredentialZone).order_by(CredentialZone.id.desc()))
    return list(result.scalars().all())


async def get_credential_zone(session: AsyncSession, zone_id: int) -> CredentialZone | None:
    return await session.get(CredentialZone, zone_id)


async def update_credential_zone(
    session: AsyncSession,
    zone_id: int,
    name: str,
    credential_ids: list[int],
    description: str | None = None,
) -> CredentialZone | None:
    """Kimlik bölgesini günceller (ad + içindeki kimlikler). Var olmayan id'ler elenir."""
    zone = await session.get(CredentialZone, zone_id)
    if zone is None:
        return None
    if name != zone.name:
        clash = await session.execute(
            select(CredentialZone).where(CredentialZone.name == name, CredentialZone.id != zone_id)
        )
        if clash.scalars().first() is not None:
            raise ValueError(f"'{name}' adında bir kimlik bölgesi zaten var.")
    valid_ids = await _existing_credential_ids(session, credential_ids)
    if not valid_ids:
        raise ValueError("En az bir geçerli kimlik seçilmeli.")
    zone.name = name
    zone.credential_ids = valid_ids
    zone.description = description
    await session.commit()
    await session.refresh(zone)
    return zone


async def delete_credential_zone(session: AsyncSession, zone_id: int) -> bool:
    zone = await session.get(CredentialZone, zone_id)
    if zone is None:
        return False
    await session.delete(zone)
    await session.commit()
    return True


async def credentials_in_zone(session: AsyncSession, zone: CredentialZone) -> list[Credential]:
    """Bölgedeki kimlikleri (id sırasıyla) döndürür."""
    if not zone.credential_ids:
        return []
    result = await session.execute(select(Credential).where(Credential.id.in_(zone.credential_ids)))
    by_id = {c.id: c for c in result.scalars().all()}
    return [by_id[i] for i in zone.credential_ids if i in by_id]
