"""Kelime listesi (Wordlist) servis fonksiyonları — CRUD + satır ayrıştırma.

Kelime listeleri dizin taraması, SMB paylaşım keşfi ve brute force için TEK kaynaktır.
``kind`` listeyi hangi taramanın tüketeceğini belirler. Yerleşik (``is_builtin``) listeler
silinemez/düzenlenemez. Satırlar JSON dizi olarak saklanır; ``parse_entries`` ham metni
(yapıştırılan veya yüklenen) temizler: boşları/yorumları (``#``) atar, sırayı koruyarak
tekilleştirir, aşırı uzun/çok sayıda satırı sınırlar.
"""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from cybersectool.core.models import Wordlist, WordlistKind

# Tek bir kelime listesi için üst sınırlar (aşırı bellek/DB şişmesini önler).
MAX_ENTRIES = 100_000
MAX_ENTRY_LEN = 255


def parse_entries(raw: str) -> list[str]:
    """Ham metni (satır/virgül ayraçlı) temiz, tekil kelime listesine dönüştürür.

    - Satır VEYA virgülle ayrılır; baş/son boşluk kırpılır.
    - Boş satırlar ve ``#`` ile başlayan yorum satırları atılır.
    - ``MAX_ENTRY_LEN`` üstü satırlar atlanır.
    - Sıra korunarak tekilleştirilir; en fazla ``MAX_ENTRIES`` satır alınır.
    """
    seen: set[str] = set()
    out: list[str] = []
    for chunk in raw.replace(",", "\n").splitlines():
        item = chunk.strip()
        if not item or item.startswith("#"):
            continue
        if len(item) > MAX_ENTRY_LEN:
            continue
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
        if len(out) >= MAX_ENTRIES:
            break
    return out


async def create_wordlist(
    session: AsyncSession,
    name: str,
    kind: WordlistKind,
    entries: list[str],
    *,
    description: str | None = None,
    created_by: int | None = None,
    is_builtin: bool = False,
) -> Wordlist:
    if not entries:
        raise ValueError("Kelime listesi boş olamaz — en az bir satır gerekli.")
    existing = await session.execute(select(Wordlist).where(Wordlist.name == name))
    if existing.scalars().first() is not None:
        raise ValueError(f"'{name}' adında bir kelime listesi zaten var.")
    wordlist = Wordlist(
        name=name,
        kind=kind,
        entries=entries,
        description=description,
        created_by=created_by,
        is_builtin=is_builtin,
    )
    session.add(wordlist)
    await session.commit()
    await session.refresh(wordlist)
    return wordlist


async def list_wordlists(session: AsyncSession, kind: WordlistKind | None = None) -> list[Wordlist]:
    """Kelime listelerini döndürür; ``kind`` verilirse yalnız o türü filtreler."""
    stmt = select(Wordlist).order_by(Wordlist.id.desc())
    if kind is not None:
        stmt = stmt.where(Wordlist.kind == kind)
    result = await session.execute(stmt)
    return list(result.scalars().all())


async def get_wordlist(session: AsyncSession, wordlist_id: int) -> Wordlist | None:
    return await session.get(Wordlist, wordlist_id)


async def update_wordlist(
    session: AsyncSession,
    wordlist_id: int,
    name: str,
    kind: WordlistKind,
    entries: list[str],
    *,
    description: str | None = None,
) -> Wordlist | None:
    """Kelime listesini günceller. Yerleşik listeler değiştirilemez (ValueError)."""
    wordlist = await session.get(Wordlist, wordlist_id)
    if wordlist is None:
        return None
    if wordlist.is_builtin:
        raise ValueError("Yerleşik kelime listesi düzenlenemez.")
    if not entries:
        raise ValueError("Kelime listesi boş olamaz — en az bir satır gerekli.")
    if name != wordlist.name:
        clash = await session.execute(
            select(Wordlist).where(Wordlist.name == name, Wordlist.id != wordlist_id)
        )
        if clash.scalars().first() is not None:
            raise ValueError(f"'{name}' adında bir kelime listesi zaten var.")
    wordlist.name = name
    wordlist.kind = kind
    wordlist.entries = entries
    wordlist.description = description
    await session.commit()
    await session.refresh(wordlist)
    return wordlist


async def delete_wordlist(session: AsyncSession, wordlist_id: int) -> bool:
    """Kelime listesini siler. Yerleşik listeler silinemez (ValueError)."""
    wordlist = await session.get(Wordlist, wordlist_id)
    if wordlist is None:
        return False
    if wordlist.is_builtin:
        raise ValueError("Yerleşik kelime listesi silinemez.")
    await session.delete(wordlist)
    await session.commit()
    return True


async def count_wordlists(session: AsyncSession) -> int:
    result = await session.execute(select(func.count()).select_from(Wordlist))
    return int(result.scalar_one() or 0)


_BUILTIN_DESC = "Yerleşik liste — değiştirilemez."


async def seed_builtin_wordlists(session: AsyncSession) -> int:
    """Yerleşik (varsayılan) kelime listelerini RECONCILE eder; net eklenen sayısını döndürür.

    Açılışta (lifespan) çağrılır. Kanonik küme (core.wordlist_defaults.builtin_wordlists):
    - Eksik olanlar eklenir (is_builtin=True).
    - Var olan YERLEŞİK listenin tür+satırları KOD'dakiyle TAZELENİR (içerik güncellemesi
      yeni açılışta otomatik yansır).
    - Kullanıcının oluşturduğu (is_builtin=False) aynı-isimli liste KORUNUR (clobber yok).
    - Artık kanonik olmayan ESKİ yerleşikler (ör. eski "(yerleşik)" adlılar) TEMİZLENİR.
    """
    from cybersectool.core.wordlist_defaults import builtin_wordlists

    canonical = builtin_wordlists()
    canonical_names = {name for name, _, _ in canonical}

    # 1) Kanonik olmayan eski yerleşikleri sil (silme güvenli — Scan.wordlist_id FK'siz).
    stale = (
        (
            await session.execute(
                select(Wordlist).where(
                    Wordlist.is_builtin.is_(True),
                    Wordlist.name.not_in(canonical_names),
                )
            )
        )
        .scalars()
        .all()
    )
    for w in stale:
        await session.delete(w)

    # 2) Kanonik listeleri ekle/tazele.
    created = 0
    changed = bool(stale)
    for name, kind, entries in canonical:
        existing = (
            await session.execute(select(Wordlist).where(Wordlist.name == name))
        ).scalar_one_or_none()
        if existing is None:
            session.add(
                Wordlist(
                    name=name,
                    kind=kind,
                    entries=entries,
                    is_builtin=True,
                    description=_BUILTIN_DESC,
                )
            )
            created += 1
            changed = True
        elif existing.is_builtin:
            # Yerleşik içeriğini koddakiyle tazele (değişmişse).
            if existing.entries != entries or existing.kind != kind:
                existing.kind = kind
                existing.entries = entries
                changed = True
        # else: kullanıcı listesi — dokunma.
    if changed:
        await session.commit()
    return created
