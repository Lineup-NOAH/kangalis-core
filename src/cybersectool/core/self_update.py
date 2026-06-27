"""Uygulama-içi OTOMATİK güncelleme — host yığınını docker.sock üzerinden yeniden kurar.

OPT-IN + ADMIN-ONLY + AUDIT'li. Varsayılan KAPALI (``AppSettings.update_apply_enabled``).
``/update`` sayfasındaki "Güncelle" butonu (yalnız açıkken + güncelleme varken) bu modülü
çağırır; bir ayrı (detached) ``docker:cli`` "güncelleyici" konteyneri başlatır. O konteyner:

    git pull --ff-only  →  docker compose -p <proje> build  →  docker compose -p <proje> up -d

Güncelleyici, app'in compose projesinin DIŞINDA (ayrı konteyner) çalışır; bu yüzden
``compose up -d`` app'i yeniden başlatırken kendisi HAYATTA kalır ve işi bitirir. App yeni
sürümle döner; ``/update`` sayfasının sürüm bilgisi değişince "tamam" sinyali olur.

GÜVENLİK (operatörün bilerek açtığı yetki): docker.sock = Docker daemon erişimi. Bu modül
create/start/remove yapar (system_health yalnız GET yapar). Bu yüzden:
  * Yalnız admin çağırabilir (route katmanı).
  * ``update_apply_enabled`` açık olmalı (varsayılan kapalı).
  * Proje adı yalnızca güvenilir compose ETİKETİNDEN gelir (web girdisi DEĞİL) ve sıkı
    doğrulanır → komut enjeksiyonu yok. Çalışma dizini yapısal ``Binds``'e konur (kabuk yok).

GEREKSİNİM: (1) kurulum bir git KLONU olmalı (zip değil — ``git pull`` gerekir),
(2) internet (apk git + imaj derleme), (3) docker.sock app'e mount edilmiş (compose'ta var).
Biri eksikse güncelleyici hata ile çıkar; app eski sürümde kalır ve sayfa "başarısız" gösterir.
ASCII-güvenli loglar (Windows konsolu).
"""

from __future__ import annotations

import contextlib
import json
import os
import re
from dataclasses import dataclass
from typing import Any

import httpx

# system_health ile aynı soket + ortam override'ı (tek kaynak).
from cybersectool.core.system_health import DOCKER_SOCK

# Güncelleyici konteynerini işaretleyen etiket — başlatma/durum/temizlik bununla bulunur.
_UPDATER_LABEL = "com.kangalis.updater"
# Sabit konteyner adı — temizlik bununla da yapılır (etiketsiz artık kalsa bile 409 olmasın).
_UPDATER_NAME = "kangalis-updater"
# Güncelleyici imajı: docker CLI + compose eklentisi içerir (Alpine; git apk ile eklenir).
_UPDATER_IMAGE = os.environ.get("KANGALIS_UPDATER_IMAGE", "docker:cli")
# Compose proje adı doğrulama: yalnız güvenli karakterler (etiketten gelir ama yine de kapı).
_PROJECT_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]*$")
_TIMEOUT = 30.0


@dataclass(frozen=True)
class UpdateLaunch:
    """``trigger_update`` sonucu — başlatıldı mı + kullanıcıya mesaj + (varsa) konteyner kimliği."""

    ok: bool
    message: str
    container_id: str | None = None


@dataclass(frozen=True)
class UpdateStatus:
    """Güncelleyici konteynerinin anlık durumu (sayfa yoklaması için)."""

    state: str  # "running" | "exited" | "none"
    exit_code: int | None = None
    log_tail: str = ""


def apply_possible() -> bool:
    """Docker soketi app'e mount edilmiş mi (otomatik güncelleme teknik olarak mümkün mü)."""
    return os.path.exists(DOCKER_SOCK)


def _client() -> httpx.AsyncClient:
    """docker.sock üzerine httpx unix-soket istemcisi (system_health ile aynı desen)."""
    transport = httpx.AsyncHTTPTransport(uds=DOCKER_SOCK)
    return httpx.AsyncClient(transport=transport, base_url="http://docker", timeout=_TIMEOUT)


async def _own_container(client: httpx.AsyncClient) -> dict[str, Any] | None:
    """Uygulamanın KENDİ konteynerini inceler (HOSTNAME = kısa konteyner kimliği)."""
    own_id = os.environ.get("HOSTNAME", "").strip()
    if not own_id:
        return None
    try:
        resp = await client.get(f"/containers/{own_id}/json")
        resp.raise_for_status()
        data: dict[str, Any] = resp.json()
        return data
    except (httpx.HTTPError, ValueError):
        return None


def _project_info(container: dict[str, Any]) -> tuple[str, str] | None:
    """Compose etiketlerinden (proje adı, HOST çalışma dizini) döndürür; yoksa None.

    ``com.docker.compose.project`` + ``com.docker.compose.project.working_dir`` compose
    tarafından deploy anında konur; güvenilir kaynak (web girdisi değil).
    """
    labels = ((container.get("Config") or {}).get("Labels")) or {}
    project = (labels.get("com.docker.compose.project") or "").strip()
    workdir = (labels.get("com.docker.compose.project.working_dir") or "").strip()
    if not project or not workdir:
        return None
    return project, workdir


async def _find_updater(client: httpx.AsyncClient) -> dict[str, Any] | None:
    """Etiketli güncelleyici konteynerini bulur (en yeni); yoksa None."""
    flt = json.dumps({"label": [f"{_UPDATER_LABEL}=1"]})
    try:
        resp = await client.get("/containers/json", params={"all": "1", "filters": flt})
        resp.raise_for_status()
        rows: list[dict[str, Any]] = resp.json()
    except (httpx.HTTPError, ValueError):
        return None
    if not rows:
        return None
    # En yeni (Created en büyük) güncelleyiciyi seç.
    rows.sort(key=lambda c: c.get("Created", 0), reverse=True)
    return rows[0]


async def _remove_container(client: httpx.AsyncClient, cid: str) -> None:
    """Eski güncelleyiciyi temizler (force; çalışıyorsa durdurup siler) — hata yutulur."""
    with contextlib.suppress(httpx.HTTPError):
        await client.delete(f"/containers/{cid}", params={"force": "1"})


async def _image_present(client: httpx.AsyncClient, ref: str) -> bool:
    try:
        resp = await client.get(f"/images/{ref}/json")
        return resp.status_code == 200
    except httpx.HTTPError:
        return False


async def _pull_image(client: httpx.AsyncClient, ref: str) -> bool:
    """docker:cli imajını çeker (yoksa). Gövdeyi (satır-satır JSON ilerleme) sonuna kadar okur.

    ÖNEMLİ: ``/images/create`` katman/çekme hatasını HTTP 200 GÖVDESİNDE (``"error"``) bildirir;
    bu yüzden yalnız status değil gövde de denetlenir (yanlış "başarı" raporu olmasın).
    """
    name, _, tag = ref.partition(":")
    try:
        # Çekme uzun sürebilir → bu çağrı için daha uzun timeout. (post tüm gövdeyi okur.)
        resp = await client.post(
            "/images/create",
            params={"fromImage": name, "tag": tag or "latest"},
            timeout=300.0,
        )
        return resp.status_code == 200 and '"error"' not in resp.text
    except httpx.HTTPError:
        return False


def _updater_cmd(project: str) -> list[str]:
    """Güncelleyicinin çalıştıracağı kabuk komutu (proje adı güvenli/doğrulanmış)."""
    # git pull --ff-only: klon değilse / yerel değişiklik varsa BAŞARISIZ (yarım güncelleme yok).
    # Proje adı -p ile zorlanır → AYNI yığını yeniden kurar (çift yığın değil).
    script = (
        "set -e; "
        "apk add --no-cache git >/dev/null 2>&1 || true; "
        "cd /project; "
        "echo '[kangalis-update] git pull...'; git pull --ff-only; "
        f"echo '[kangalis-update] build...'; docker compose -p {project} build; "
        f"echo '[kangalis-update] up...'; docker compose -p {project} up -d; "
        "echo '[kangalis-update] DONE'"
    )
    return ["sh", "-c", script]


async def trigger_update() -> UpdateLaunch:
    """Güncelleyici konteynerini başlatır (detached). ASLA istisna fırlatmaz.

    Akış: docker.sock var mı → kendi konteyneri incele → compose proje+dizin etiketleri →
    eski güncelleyiciyi temizle → docker:cli imajını sağla → create+start. Dönen mesaj
    kullanıcıya gösterilir.
    """
    if not os.path.exists(DOCKER_SOCK):
        return UpdateLaunch(
            False, "Docker soketi yok — otomatik güncelleme bu kurulumda kullanılamaz."
        )
    async with _client() as client:
        own = await _own_container(client)
        if own is None:
            return UpdateLaunch(False, "Uygulama konteyneri bulunamadı (Docker API).")
        info = _project_info(own)
        if info is None:
            return UpdateLaunch(
                False,
                "Compose proje bilgisi okunamadi — otomatik guncelleme "
                "yalniz docker compose kurulumunda calisir.",
            )
        project, workdir = info
        if not _PROJECT_RE.match(project):
            return UpdateLaunch(False, f"Compose proje adi gecersiz: {project!r}")

        # Süren bir güncelleme varsa İKİNCİSİNİ başlatma (yarış + çift compose-up önlenir).
        old = await _find_updater(client)
        if old is not None and old.get("State") == "running":
            return UpdateLaunch(False, "Guncelleme zaten suruyor — bitmesini bekle.")
        # Eski (bitmiş) güncelleyiciyi etiketten VE sabit addan temizle (409 ad-cakismasi onlenir).
        if old is not None:
            await _remove_container(client, str(old.get("Id") or ""))
        await _remove_container(client, _UPDATER_NAME)

        # docker:cli imajını sağla (yoksa çek). Kısa-devre: zaten varsa çekme denenmez.
        if not await _image_present(client, _UPDATER_IMAGE) and not await _pull_image(
            client, _UPDATER_IMAGE
        ):
            return UpdateLaunch(
                False,
                f"Guncelleyici imaji ({_UPDATER_IMAGE}) cekilemedi — "
                "internet baglantisini kontrol et.",
            )

        body = {
            "Image": _UPDATER_IMAGE,
            "Cmd": _updater_cmd(project),
            "WorkingDir": "/project",
            "Labels": {_UPDATER_LABEL: "1"},
            "HostConfig": {
                "Binds": [
                    f"{workdir}:/project",
                    f"{DOCKER_SOCK}:/var/run/docker.sock",
                ],
                "AutoRemove": False,
                "RestartPolicy": {"Name": "no"},
            },
        }
        try:
            create = await client.post(
                "/containers/create",
                params={"name": _UPDATER_NAME},
                json=body,
            )
            if create.status_code not in (200, 201):
                return UpdateLaunch(
                    False, f"Guncelleyici olusturulamadi (HTTP {create.status_code})."
                )
            cid = str(create.json().get("Id") or "")
            start = await client.post(f"/containers/{cid}/start")
            if start.status_code not in (200, 204):
                return UpdateLaunch(
                    False, f"Guncelleyici baslatilamadi (HTTP {start.status_code})."
                )
        except (httpx.HTTPError, ValueError) as exc:
            return UpdateLaunch(False, f"Docker API hatasi: {exc}")
    return UpdateLaunch(True, "Guncelleme baslatildi.", container_id=cid)


async def update_status() -> UpdateStatus:
    """Güncelleyici konteynerinin durumunu + log kuyruğunu döndürür (sayfa yoklaması).

    ``state``: running (sürüyor) / exited (bitti; ``exit_code``) / none (güncelleyici yok).
    App yeniden başladıktan sonra da etiketle bulur (bellekten bağımsız).
    """
    if not os.path.exists(DOCKER_SOCK):
        return UpdateStatus(state="none")
    async with _client() as client:
        row = await _find_updater(client)
        if row is None:
            return UpdateStatus(state="none")
        cid = str(row.get("Id") or "")
        # Anlık durum + çıkış kodu için inspect.
        state = "running" if row.get("State") == "running" else "exited"
        exit_code: int | None = None
        try:
            ins = await client.get(f"/containers/{cid}/json")
            if ins.status_code == 200:
                st = ins.json().get("State") or {}
                running = bool(st.get("Running"))
                state = "running" if running else "exited"
                if not running:
                    exit_code = st.get("ExitCode")
        except (httpx.HTTPError, ValueError):
            pass
        # Log kuyruğu (son ~40 satır) — hata teşhisi için.
        log_tail = ""
        try:
            logs = await client.get(
                f"/containers/{cid}/logs",
                params={"stdout": "1", "stderr": "1", "tail": "40"},
            )
            if logs.status_code == 200:
                # Docker multiplexed stream başlıklarını (8-bayt) kabaca temizle.
                log_tail = _demux_logs(logs.content)
        except httpx.HTTPError:
            pass
    return UpdateStatus(state=state, exit_code=exit_code, log_tail=log_tail)


def _demux_logs(raw: bytes) -> str:
    """Docker (TTY'siz) log akışındaki 8-baytlık çerçeve başlıklarını ayıklar → düz metin.

    Çerçeve: [stream(1)][000][size(4, big-endian)][payload]. TTY'li ise başlık yok; o
    durumda ham metni döndürür. ASCII-güvenli (decode errors='replace').
    """
    out: list[str] = []
    i, n = 0, len(raw)
    framed = False
    while i + 8 <= n:
        header = raw[i : i + 8]
        if header[0] in (1, 2) and header[1] == 0 and header[2] == 0 and header[3] == 0:
            size = int.from_bytes(header[4:8], "big")
            chunk = raw[i + 8 : i + 8 + size]
            out.append(chunk.decode("utf-8", "replace"))
            i += 8 + size
            framed = True
        else:
            break
    if not framed:
        return raw.decode("utf-8", "replace").strip()[-2000:]
    return "".join(out).strip()[-2000:]
