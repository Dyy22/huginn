# 🛡️ CVE Threat Radar — Go Discord Bot & Webhook Tracker

Bot Discord berbasis **Go (`discordgo`)** yang terintegrasi dengan **NVD NIST API v2.0** dan **CISA KEV (Known Exploited Vulnerabilities)** untuk:
1. **Rich Embed Webhook & Channel Auto-Alerts** — Polling berkala CVE terbaru dengan filter minimum severity (`CRITICAL`/`HIGH`/`MEDIUM`/`LOW`), dynamic keyword/vendor watchlist, dan deduplikasi SQLite (`modernc.org/sqlite`, pure Go tanpa CGO).
2. **Enrichment CISA KEV Otomatis** — Setiap CVE yang dicari atau di-poll otomatis dicek ke katalog CISA KEV. Jika sedang dieksploitasi aktif di lapangan (*in the wild*), embed berubah menjadi neon-crimson dengan badge peringatan khusus, info *Patch Due Date*, dan status pemakaian *Ransomware*.
3. **Slash Commands (`/cve`)** — Cari CVE berdasarkan keyword, lookup CVE ID spesifik, cek daftar CISA KEV terbaru, dan kelola watchlist langsung dari Discord.

---

## 📂 Struktur Project

```text
/home/perdy/Documents/discord-bot
├── cmd/cvebot/main.go          # Entry point (Daemon Bot + One-shot CLI tester)
├── internal/
│   ├── config/config.go        # Konfigurasi via .env
│   ├── cve/
│   │   ├── types.go            # Normalized CVEItem & KEVEntry structs
│   │   ├── nvd.go              # Client NVD API v2.0 (tail-pagination + rate-limiter)
│   │   └── kev.go              # Client & in-memory cache CISA KEV catalog
│   ├── discord/
│   │   ├── bot.go              # Slash command handler & background poller
│   │   ├── embeds.go           # Builder Discord Rich Embed (color-coded + CVSS bar)
│   │   └── webhook.go          # Webhook sender (batching 10 embeds/msg)
│   └── store/sqlite.go         # SQLite store (seen_cves, watchlist, settings)
├── .env.example                # Template environment variable
└── cvebot                      # Compiled binary
```

---

## 🚀 Cara Pakai Cepat

### 1. Setup `.env`
```bash
cp .env.example .env
```
Isi variabel berikut di `.env`:
- `DISCORD_BOT_TOKEN` & `DISCORD_APP_ID` (dari [Discord Developer Portal](https://discord.com/developers/applications))
- `DISCORD_GUILD_ID` (opsional tapi disarankan supaya Slash Command `/cve` langsung muncul instan di server tanpa nunggu propagasi global 1 jam)
- `DISCORD_WEBHOOK_URL` (URL webhook channel Discord untuk pengiriman Rich Embed)
- `NVD_API_KEY` (opsional, menaikkan rate limit NVD dari 5 req/30s menjadi 50 req/30s)

### 2. Test Langsung dari Terminal (Mode CLI / Tanpa Bot Token)
Kamu bisa langsung ngetes pencarian CVE dan kirim ke Webhook tanpa nyalain daemon bot:
```bash
# Lookup 1 CVE spesifik (termasuk cek status CISA KEV)
./cvebot -cve CVE-2021-44228

# Search CVE berdasarkan keyword + filter severity
./cvebot -search fortinet -severity CRITICAL -limit 3

# Search sekaligus tembak Rich Embed ke DISCORD_WEBHOOK_URL di .env
./cvebot -search openssh -severity HIGH -limit 2 -send-webhook
```

### 3. Jalankan Bot Daemon (Slash Commands + Background Poller)
```bash
./cvebot
```

---

## 💬 Daftar Slash Commands di Discord

| Command | Fungsi |
| :--- | :--- |
| `/cve search keyword:<text> [severity] [limit] [push_webhook]` | Cari CVE terbaru berdasarkan keyword/vendor/produk, urut dari yang paling baru, dengan opsi langsung forward ke Webhook. |
| `/cve lookup id:<CVE-YYYY-NNNN> [push_webhook]` | Tampilkan detail lengkap Rich Embed untuk 1 CVE ID spesifik. |
| `/cve kev [keyword] [limit]` | Tampilkan daftar kerentanan terbaru yang sedang aktif dieksploitasi menurut katalog **CISA KEV**. |
| `/cve watch add keyword:<text>` | Tambah keyword/vendor ke watchlist otomatis (disimpan di SQLite). |
| `/cve watch remove keyword:<text>` | Hapus keyword dari watchlist. |
| `/cve watch severity level:<CRITICAL\|HIGH\|MEDIUM\|LOW>` | Ubah batas minimum severity untuk auto-alert. |
| `/cve watch list` | Lihat status konfigurasi tracker, daftar keyword aktif, dan jumlah CVE yang sudah tercatat di database. |
| `/cve poll-now` | Paksa bot melakukan polling NVD + CISA KEV saat itu juga dan kirim temuan baru ke Webhook/Channel. |
