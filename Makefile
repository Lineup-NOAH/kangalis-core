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

ai: ## Yerel AI motorunu başlat (opsiyonel — ~5GB model indirir)
	docker compose --profile ai up -d llamacpp

.PHONY: help up setup down reset logs ps ai
