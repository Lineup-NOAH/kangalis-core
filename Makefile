# Kangalis — geliştirme/işletim kısayolları (Linux/macOS; Windows'ta setup.ps1 kullanın).
.DEFAULT_GOAL := help

help: ## Komutları listele
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-10s\033[0m %s\n",$$1,$$2}'

up: ## Servisleri derle + başlat (nmap dahil)
	docker compose up -d --build

setup: ## İlk kurulum sihirbazı (admin kullanıcı + tarama kapsamı)
	bash setup.sh

down: ## Servisleri durdur (veri KALIR)
	docker compose down

reset: ## Servisleri durdur + TÜM VERİYİ SİL
	docker compose down -v

logs: ## Logları canlı izle
	docker compose logs -f

ps: ## Servis durumu
	docker compose ps

ai: ## Yerel AI (Ollama) motorunu başlat (opsiyonel — sonra: ollama pull qwen3:8b)
	docker compose --profile ai up -d ollama
	@echo "Model çek: docker compose exec ollama ollama pull qwen3:8b  (ya da: make ai-baked = model gömülü)"

ai-build: ## Ön-paketli AI imajını (model gömülü) yerelde derle
	bash build-ai-image.sh

ai-baked: ## Ön-paketli (model gömülü) AI imajıyla başlat — çalışma anında sıfır indirme
	docker compose -f docker-compose.yml -f docker-compose.ai-baked.yml --profile ai up -d ollama

.PHONY: help up setup down reset logs ps ai ai-build ai-baked
