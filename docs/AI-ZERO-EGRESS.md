# Kangalis Local AI — Zero-Egress (No Data Leaves the Box) Verification Runbook

> **Goal:** Independently prove that Kangalis's local AI assistant does **not** send the
> vulnerability/finding data it analyzes **outside the deployment network**. This document is a
> repeatable audit procedure for both the internal team and the operator's security/compliance
> (GDPR, ISO 27001) team.

## 1. Architecture — why data cannot leave

The AI is made up of three layers, and **all three run on the operator's own server**:

| Layer | Role | Location |
|--------|-------|-------|
| **Kangalis AI framework** (`core/ai/`) | Builds the request, assembles the prompt, displays the response | Deployment server (application container) |
| **Local inference engine** (Ollama; local engines such as LM Studio/LocalAI also work) | Loads the model, serves an OpenAI-compatible API | Deployment server (AI container) |
| **Model** (e.g. qwen3:8b) | The AI that generates the text | Deployment server (on local disk) |

There is **no** cloud API. The AI call only goes to an **internal-network address**
(`http://ollama:11434/v1`) — this is a Docker internal-DNS name, not an internet IP; it physically
cannot leave the host machine. While the model is "thinking" it uses only the local CPU + disk and
opens no external connection.

## 2. Three independent proof methods

### Proof A — Code audit (single egress point)

The **only** external-network call in the `core/ai/` package is `client.py`. Verify:

```bash
# All HTTP client usages in the package — only client.py should appear:
grep -rn "httpx\|requests\.\|urllib\|aiohttp" src/cybersectool/core/ai/

# Cloud-provider / API-key traces — RESULT must be EMPTY:
grep -rni "openai.com\|anthropic\|api_key\|sk-\|bearer" src/cybersectool/core/ai/
```

`client.py` only goes to the **endpoint configured in Settings** (`AppSettings.ai_endpoint_url`); no
other target is baked in. The egress point is single and auditable.

### Proof B — The configured endpoint is on the internal network

```bash
docker compose exec -T app python -c "
import asyncio
from cybersectool.core.db import SessionLocal
from cybersectool.core.app_settings import get_settings
async def m():
    async with SessionLocal() as s:
        r = await get_settings(s)
        print('endpoint =', r.ai_endpoint_url)
asyncio.run(m())"
# Expected: endpoint = http://ollama:11434/v1   (internal Docker-DNS name, not the internet)
```

### Proof C — Zero internet connections at runtime

While the AI is actually generating, read the AI container's active connections. There must not be
**a single connection** to a public-internet IP:

```bash
# Start a generation in the background:
docker compose exec -T app python -c "
import asyncio
from cybersectool.core.ai.service import AIConfig, generate
c = AIConfig(True,'http://ollama:11434/v1','qwen3:8b',180.0)
asyncio.run(generate(c,'Apache CVE-2021-41773 nedir?',system='Sen analistsin.'))" &

# While the generation is running, resolve the AI container's ESTABLISHED connections:
docker exec kangalis-ai cat /proc/net/tcp /proc/net/tcp6 | awk '$4=="01"{print $3}'
# (Hex IP:PORT — only 127.x / 172.x / 10.x / 192.168.x = internal network should appear)
```

**Live result in this repo:** during generation, the only established connection was `127.0.0.1`
(the model's own internals); public-internet connections were **ZERO**. ✅

## 3. Definitive proof — Air-Gap (cut-the-internet) test

The strongest proof: **completely cut** the AI container's internet, and the AI **must still work**.
If it phoned home it would break — it doesn't.

> ⚠️ This test affects the AI service for a few minutes; run it during a maintenance window, with
> operator approval. All steps are reversible; in the worst case, `docker compose up -d` +
> `docker restart kangalis-ai` fully restores networking.

> **Note (security bonus):** by default the AI container runs without the `NET_ADMIN` capability →
> it cannot even modify its own network routes (`ip route del` → *Operation not permitted*).
> That is why the internet is cut from the **Docker network layer**, not from *inside* the container:

```bash
# 1) Create an internet-less internal network; keep app access, DISCONNECT the AI from the internet-facing network:
docker network create --internal kg-airgap
docker network connect    kg-airgap          kangalis-core-app-1   # app access is preserved
docker network connect    kg-airgap          kangalis-ai
docker network disconnect kangalis-core_default kangalis-ai        # ← internet is gone

# 2) VERIFY that the internet is really cut (BLOCKED is expected):
docker exec kangalis-ai sh -c "curl -m6 -sS https://www.google.com >/dev/null 2>&1 && echo REACHABLE || echo BLOCKED"

# 3) TRY an AI generation — it MUST WORK even with no internet:
docker compose exec -T app python -c "
import asyncio
from cybersectool.core.ai.service import AIConfig, generate
c = AIConfig(True,'http://ollama:11434/v1','qwen3:8b',180.0)
print(asyncio.run(generate(c,'Write a short test sentence.',system='You are an analyst.')))"
# Expected: the model produces a normal response → NO data needs to leave.

# 4) ROLL BACK (reconnect the AI to the internet-facing network + clean up the test network):
docker network connect    kangalis-core_default kangalis-ai
docker network disconnect kg-airgap kangalis-ai
docker network disconnect kg-airgap kangalis-core-app-1
docker network rm         kg-airgap
```

**Run live in this repo (2026-06-13):** after step 1, `curl` → **BLOCKED**; in step 3 the model
produced a normal response with no internet (*"Redis authentication ... is critically important to
prevent unauthorized access."*). After rollback, the internet was REACHABLE, the AI endpoint OK, and
the containers healthy. ✅ **The AI does NOT need the internet; data does not leave the box.**

> Permanent method in production: keep the AI container on a Docker `--internal` network at all times,
> or DROP the container's egress in the host firewall (iptables/Windows Defender Firewall). In that
> case the internet is never opened; the model ships with pre-downloaded weights (baked into the image).

## 4. Independent network monitoring (for the operator's auditor)

Packet-level verification from the host (Wireshark/tcpdump):

```bash
# Find the AI container's bridge interface, then watch outbound packets during generation:
sudo tcpdump -ni any "host kangalis-ai and not (net 172.16.0.0/12 or net 10.0.0.0/8 or net 192.168.0.0/16)"
# Trigger an AI generation → this command's output must stay EMPTY (no packets to the public internet).
```

## 5. The one honest exception — model download (NOT data)

Data never leaves; however, **on first install** the local inference engine downloads the model (the
qwen3 *weight files*) from a public model repository. This:

- **Is not operator/deployment data** — it is only generic, open-source model weights (one direction: download).
- **Is one-time** — once the model is on disk it is never needed again.
- **Never happens in an air-gapped deployment** — the model ships pre-baked into the product image
  (`docker load`), for zero install-time egress.

## 6. Summary

| Question | Answer |
|------|-------|
| Does data go to the cloud? | **No** — no cloud API, no key (Proof A). |
| Where does the AI connect? | Only the internal-network `ollama:11434` (Proof B). |
| Does it connect to the internet at runtime? | **No** — 0 public-internet connections (Proof C). |
| Does it work without the internet? | **Yes** — the air-gap test passes (Section 3). |
| Is there any external traffic at all? | Only the one-time model download; in an air-gapped setup, not even that (Section 5). |

**Conclusion:** Kangalis's local AI does not send operator data outside the network; this can be
independently verified through code audit, runtime network analysis, and the air-gap test.
