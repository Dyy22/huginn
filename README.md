<div align="center">

# 🐦‍⬛ Huginn

**Tactical CVE, CISA KEV & Cybersecurity Threat Intelligence Discord Bot**

[![Go Version](https://img.shields.io/badge/Go-1.23+-00ADD8?style=flat-square&logo=go)](https://go.dev/)
[![Docker](https://img.shields.io/badge/Docker-Alpine%20%7C%20~21MB-2496ED?style=flat-square&logo=docker&logoColor=white)](./Dockerfile)
[![NIST NVD](https://img.shields.io/badge/Feed-NIST%20NVD%20v2.0-003366?style=flat-square)](https://nvd.nist.gov/developers/vulnerabilities)
[![CISA KEV](https://img.shields.io/badge/Exploit%20Intel-CISA%20KEV-FF0055?style=flat-square)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
[![License: MIT](https://img.shields.io/badge/License-MIT-2ECC71?style=flat-square)](./LICENSE)

*Named after Odin's raven who flies across Midgard to gather intelligence — **Huginn** continuously monitors the **NIST NVD v2.0 API**, the **CISA Known Exploited Vulnerabilities (KEV)** catalog, and **8+ top cybersecurity research feeds**, delivering rich, actionable threat intelligence cards directly to your Discord channels.*

</div>

---

## ✨ Key Features

### 🛡️ 1. Real-Time CVE & CISA KEV Radar (`/cve`)
- **Automated NVD v2.0 Polling & Tail-Pagination:** Queries NIST NVD v2.0 with automatic tail-page fetching so keyword searches and background polls always return the **newest** vulnerabilities rather than legacy records.
- **Automatic CISA KEV Cross-Enrichment:** Every CVE is cross-referenced against the in-memory **CISA Known Exploited Vulnerabilities** catalog. Actively exploited CVEs are highlighted in neon-crimson (`#FF0055`) with patch due dates, ransomware campaign indicators, and mandated remediation actions.
- **Tactical Rich Embeds:**
  - **3-Column Inline Grid:** CVSS v3.1/v4.0 score bar (`████████░░`), affected vendor/product/version range (`cve.affected` + CPE 2.3), and human-readable CWE classification (e.g., `CWE-89` → *SQL Injection (SQLi)*).
  - **Exploitability Badges:** Translates raw CVSS vectors into instant visual badges (`🌐 Network` • `⚡ Low Complexity` • `🔓 No Auth Required` • `🎯 Zero-Click` • `💥 Scope Changed`).
  - **Threat Hunting Pivot Links:** Direct one-click links to NVD Detail, CVE.org, and GitHub PoC repository search.

### 📰 2. Curated Cybersecurity News, Research & Writeups (`/news`)
- **Multi-Source Concurrent RSS/Atom Engine:** Aggregates articles across three curated categories:
  - 🔥 **`breaking`** — *The Hacker News*, *BleepingComputer*, *Dark Reading*
  - 🔬 **`research`** — *Google Project Zero*, *PortSwigger Research*, *watchTowr Labs*, *Zero Day Initiative (ZDI)*
  - 🎯 **`writeups`** — *Intigriti Bug Bytes*
- **Auto-CVE Extraction & KEV Tagging:** Automatically scans article headlines and summaries for `CVE-YYYY-NNNN` identifiers, attaches clickable NVD badges to the news embed, and flags any CVE present in the **CISA KEV** catalog.

### ⚙️ 3. Zero-Config Channel Binding & Live-Reload Intervals
- **Context-Aware Channel Binding:** Run `/cve watch add` in `#cve-alerts` and `/news watch add` in `#cyber-news` — Huginn automatically binds each feed to the channel where the command was executed.
- **Independent Live-Reload Tickers:** Adjust CVE and News polling intervals independently on the fly (`/cve watch interval` and `/news watch interval`) without restarting the container.
- **Pure-Go SQLite Deduplication (`CGO_ENABLED=0`):** Uses `modernc.org/sqlite` to persist seen CVEs, seen articles, watched severities/categories, and polling intervals inside a lightweight ~21 MB static Alpine container.

---

## 💬 Slash Commands Reference

### `/cve` — Vulnerability & Exploit Intelligence

| Command | Description |
| :--- | :--- |
| `/cve search keyword:<text> [severity] [limit]` | Search newest CVEs by vendor, product, or vulnerability keyword with optional CVSS severity filter (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`). |
| `/cve lookup id:<CVE-YYYY-NNNN>` | Inspect full tactical Rich Embed for a specific CVE ID (e.g., `CVE-2024-6387`). |
| `/cve kev [keyword] [limit]` | Browse the latest actively exploited vulnerabilities from the **CISA KEV** catalog. |
| `/cve watch add severity:<level>` | Subscribe the current channel to auto-alerts for a severity level (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`). |
| `/cve watch remove severity:<level>` | Remove a severity level from the auto-tracker watchlist. |
| `/cve watch interval duration:<time>` | Dynamically update the CVE polling interval (e.g., `5m`, `15m`, `30m`, `1h`). |
| `/cve watch list` | Display watched severities, bound alert channel, polling interval, and total tracked CVEs. |
| `/cve poll-now` | Trigger an immediate NVD + CISA KEV poll cycle. |

### `/news` — Cybersecurity News & Writeup Radar

| Command | Description |
| :--- | :--- |
| `/news latest [category] [limit]` | Fetch the newest articles from `all`, `breaking`, `research`, or `writeups`. |
| `/news search keyword:<text> [limit]` | Search across all cybersecurity RSS feeds by keyword, vendor, or CVE ID. |
| `/news watch add [category]` | Bind the current channel to receive automated news alerts (`all`, `breaking`, `research`, or `writeups`). |
| `/news watch remove [category]` | Unsubscribe a news category from automated alerts. |
| `/news watch interval duration:<time>` | Dynamically update the News polling interval (e.g., `15m`, `30m`, `1h`). |
| `/news watch list` | Display watched news categories, bound channel, polling interval, and tracked article count. |
| `/news poll-now` | Trigger an immediate RSS feed poll cycle. |

---

## 🚀 Quick Start

### Prerequisites
1. Create a Discord Application & Bot at the [Discord Developer Portal](https://discord.com/developers/applications).
2. Enable **`applications.commands`** and **`bot`** scopes under **Installation** (with `Send Messages`, `Embed Links`, and `Use Slash Commands` permissions) and invite the bot to your server.
3. *(Optional)* Request a free [NIST NVD API Key](https://nvd.nist.gov/developers/request-an-api-key) to increase the NVD rate limit from 5 requests/30s to 50 requests/30s.

### Option A: Docker Compose (Recommended)

```bash
git clone https://github.com/Dyy22/huginn.git
cd huginn
cp .env.example .env
```

Edit `.env` and set your credentials:
```env
DISCORD_BOT_TOKEN=your_discord_bot_token_here
DISCORD_APP_ID=your_discord_application_id_here
NVD_API_KEY=your_optional_nvd_api_key
DB_PATH=/data/cve_tracker.db
```

Launch the container:
```bash
docker compose up -d --build
docker compose logs -f
```

### Option B: Build from Source (Go 1.23+)

```bash
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o cvebot ./cmd/cvebot
./cvebot
```

#### One-Shot CLI Mode (Testing without Discord Bot Daemon)
You can also query NVD + CISA KEV directly from your terminal:
```bash
# Lookup a specific CVE ID
./cvebot -cve CVE-2021-44228

# Search newest CVEs by keyword and severity
./cvebot -search fortinet -severity CRITICAL -limit 3
```

---

## 📂 Project Architecture

```text
huginn/
├── cmd/cvebot/
│   └── main.go                 # Entrypoint, independent CVE & News poller goroutines, CLI mode
├── internal/
│   ├── config/
│   │   └── config.go           # Environment configuration loader
│   ├── cve/
│   │   ├── types.go            # Normalized CVEItem & KEVEntry models
│   │   ├── nvd.go              # NIST NVD API v2.0 client (rate-limiting + tail pagination)
│   │   └── kev.go              # CISA KEV catalog client & thread-safe in-memory cache
│   ├── news/
│   │   └── feeds.go            # Concurrent RSS 2.0 / Atom parser & CVE regex extractor
│   ├── discord/
│   │   ├── bot.go              # Discord gateway handlers (/cve & /news) + pollers
│   │   └── embeds.go           # Rich Embed builders, CWE mapper & CVSS vector humanizer
│   └── store/
│       └── sqlite.go           # Pure-Go SQLite persistence & deduplication store
├── Dockerfile                  # Multi-stage static Alpine build (~21MB image)
├── docker-compose.yml          # Production Compose definition with named volume persistence
└── .env.example                # Environment template
```

---

## 📄 License

Released under the [MIT License](./LICENSE).
