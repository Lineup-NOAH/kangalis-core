# CyberSecTool uygulama imaji (uv tabanli)
FROM python:3.12-slim

# uv'yi resmi imajdan kopyala
COPY --from=ghcr.io/astral-sh/uv:0.11.17 /uv /uvx /bin/

# Sistem araçları: PDF rapor için WeasyPrint (Pango/Cairo)
# çalışma zamanı kütüphaneleri + Türkçe karakterleri kapsayan DejaVu fontları.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpango-1.0-0 \
        libpangoft2-1.0-0 \
        libharfbuzz0b \
        libffi8 \
        fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PATH="/app/.venv/bin:$PATH"

# Once yalnizca bagimliliklar (Docker katman cache'i icin)
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-install-project --no-dev

# Uygulama kodu
COPY . .
RUN uv sync --frozen --no-dev

EXPOSE 8000
CMD ["uvicorn", "cybersectool.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
