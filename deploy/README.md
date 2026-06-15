# Kangalis (CyberSecTool) — Kubernetes dağıtımı

`deploy/helm/kangalis` Helm chart'ı uygulamayı (app/worker/beat + opsiyonel postgres/redis/mcp)
Kubernetes'e kurar. Tarama **worker'ları yatay ölçeklenir** (replica artırımı = daha çok eşzamanlı
tarama). Tek bir büyük taramayı pod'lara dağıtan **fan-out** ayrı bir adımdır (aşağıda "Yol haritası").

## Mimari (neden böyle)
İki ağ kaygısı ayrıdır:
1. **İç servisler** (db/redis/app/worker-kontrol) — küme ağında.
2. **Tarama-hedef erişimi** — worker'ın hedef VLAN'a ulaşması gerekir. NAT arkasından büyük süpürme
   güvenilmez (bkz. memory/araç notları). Çözüm: worker'ı hedef ağa **sensör** olarak bağla
   (`worker.hostNetwork=true` veya Multus ile ikincil NIC). Bu, Nessus/OpenVAS sensör modelidir.

## Hızlı başlangıç (yerel — kind)
```bash
# 1) İmajı derle + kind kümesine yükle (registry gerektirmez)
docker build -t cybersectool-app:latest .
kind create cluster --name kangalis
kind load docker-image cybersectool-app:latest --name kangalis

# 2) Kur (dev değerleri)
helm install kangalis ./deploy/helm/kangalis \
  -n kangalis --create-namespace \
  -f deploy/helm/kangalis/values-dev.yaml

# 3) Eriş
kubectl -n kangalis port-forward svc/kangalis-app 8000:8000
# → http://localhost:8000/
```

## Üretim kurulumu
```bash
helm install kangalis ./deploy/helm/kangalis -n kangalis --create-namespace \
  --set appEnv=production \
  --set secrets.secretKey=$(openssl rand -hex 32) \
  --set secrets.credentialEncryptionKey=$(openssl rand -hex 32) \
  --set postgres.password=$(openssl rand -hex 16) \
  --set worker.replicas=4 \
  --set worker.hostNetwork=true \
  --set image.repository=REGISTRY/cybersectool-app --set image.tag=VERSION --set image.pullPolicy=Always
```

### Önemli değerler
| Değer | Açıklama |
|---|---|
| `worker.replicas` | Eşzamanlı tarama kapasitesi (throughput ölçeklemesi) |
| `worker.hostNetwork` | Tarayıcı hedef LAN/VLAN'a NAT'sız erişsin (sensör). Node ağını kullanır |
| `worker.netRaw` | nmap raw soket (`-sS`/`-sn`) için `CAP_NET_RAW` (varsayılan açık) |
| `worker.autoscaling.enabled` | CPU'ya göre HPA |
| `postgres.enabled` | `false` → dış/yönetilen DB (`externalDatabaseUrl`) |
| `redis.enabled` | `false` → dış Redis (`externalRedisUrl`) |
| `app.ingress.enabled` | Web arayüzü için Ingress |
| `secrets.*` | **production'da MUTLAKA override** (NOTES uyarır) |

## Şema göçü
`migrations.enabled=true` (varsayılan) ile her `helm install/upgrade` sonrası `alembic upgrade head`
bir **post-install/upgrade hook Job**'u olarak koşar (DB hazır olana dek bekler).

## Worker'ları ölçekle
```bash
kubectl -n kangalis scale deploy/kangalis-worker --replicas=6
```

## Yol haritası (Faz 2b — bu chart'ta DEĞİL)
- **Tek-tarama fan-out:** bir `/24` taramasının `/27` bloklarını Celery alt-görevleriyle worker
  pod'larına dağıt → tek taramanın süresi worker sayısıyla ~doğrusal düşer.
- **Segment-başına kuyruk** (`scan.vlanX`) + node-affinity ile her worker'ı bir ağ segmentine sabitle.
- **Multus** ile worker pod'una hedef VLAN'da ikincil NIC (hostNetwork yerine üretim-grade).
