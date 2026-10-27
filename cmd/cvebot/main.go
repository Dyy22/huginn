package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"cve-discord-bot/internal/config"
	"cve-discord-bot/internal/cve"
	"cve-discord-bot/internal/discord"
	"cve-discord-bot/internal/store"
)

func main() {
	var (
		cliSearch   = flag.String("search", "", "CLI test: Search CVEs by keyword without starting the bot daemon")
		cliCVE      = flag.String("cve", "", "CLI test: Lookup a specific CVE ID (e.g. CVE-2024-6387)")
		cliSeverity = flag.String("severity", "", "CLI test: Filter by CVSS v3 severity (LOW, MEDIUM, HIGH, CRITICAL)")
		cliLimit    = flag.Int("limit", 3, "CLI test: Max results to fetch (default 3)")
	)
	flag.Parse()

	cfg := config.Load()
	kevClient := cve.NewKEVClient()
	nvdClient := cve.NewNVDClient(cfg.NVDAPIKey, kevClient)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// One-shot CLI mode for testing NVD + KEV without needing Bot daemon
	if *cliSearch != "" || *cliCVE != "" {
		runCLIMode(ctx, nvdClient, *cliSearch, *cliCVE, *cliSeverity, *cliLimit)
		return
	}

	log.Printf("[BOOT] Opening SQLite database at %s...", cfg.DBPath)
	st, err := store.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("[FATAL] Failed to open SQLite store (%s): %v", cfg.DBPath, err)
	}
	defer st.Close()

	if err := kevClient.EnsureLoaded(ctx); err != nil {
		log.Printf("[WARN] Initial CISA KEV fetch failed (will retry): %v", err)
	}

	if cfg.DiscordBotToken == "" {
		log.Fatalf("[FATAL] DISCORD_BOT_TOKEN is not configured in .env")
	}

	bot, err := discord.NewBot(cfg, nvdClient, kevClient, st)
	if err != nil {
		log.Fatalf("[FATAL] Failed to initialize Discord bot: %v", err)
	}

	if err := bot.Start(ctx); err != nil {
		log.Fatalf("[FATAL] Failed to start Discord bot: %v", err)
	}
	defer bot.Stop()

	sevs, _ := st.ListSeverities()
	newsCats, _ := st.ListNewsCategories()
	cveInterval := st.GetPollInterval(cfg.DefaultCVEPollInterval)
	newsInterval := st.GetNewsPollInterval(cfg.DefaultNewsPollInterval)

	log.Printf("[BOOT] Huginn is online!")
	log.Printf("[BOOT]   • CVE Poller  : every %s | WatchedSeverities=%v | Channel=%s | SeenCVEs=%d",
		cveInterval, sevs, emptyOrNone(st.GetAlertChannel("")), st.SeenCount())
	log.Printf("[BOOT]   • News Poller : every %s | WatchedCategories=%v | Channel=%s | SeenNews=%d",
		newsInterval, newsCats, emptyOrNone(st.GetNewsAlertChannel("")), st.SeenNewsCount())

	// 1. Independent CVE Background Poller
	go func() {
		ticker := time.NewTicker(cveInterval)
		defer ticker.Stop()

		select {
		case <-ctx.Done():
			return
		case newDur := <-bot.CVEIntervalUpdates():
			ticker.Reset(newDur)
			log.Printf("[CVE-POLLER] Ticker dynamically updated to %s", newDur)
		case <-time.After(10 * time.Second):
			if _, err := bot.RunPollCycle(ctx); err != nil {
				log.Printf("[CVE-POLLER] Error: %v", err)
			}
		}

		for {
			select {
			case <-ctx.Done():
				return
			case newDur := <-bot.CVEIntervalUpdates():
				ticker.Reset(newDur)
				log.Printf("[CVE-POLLER] Ticker dynamically updated to %s", newDur)
			case <-ticker.C:
				if _, err := bot.RunPollCycle(ctx); err != nil {
					log.Printf("[CVE-POLLER] Error: %v", err)
				}
			}
		}
	}()

	// 2. Independent News Background Poller
	go func() {
		ticker := time.NewTicker(newsInterval)
		defer ticker.Stop()

		select {
		case <-ctx.Done():
			return
		case newDur := <-bot.NewsIntervalUpdates():
			ticker.Reset(newDur)
			log.Printf("[NEWS-POLLER] Ticker dynamically updated to %s", newDur)
		case <-time.After(15 * time.Second):
			if _, err := bot.RunNewsPollCycle(ctx); err != nil {
				log.Printf("[NEWS-POLLER] Error: %v", err)
			}
		}

		for {
			select {
			case <-ctx.Done():
				return
			case newDur := <-bot.NewsIntervalUpdates():
				ticker.Reset(newDur)
				log.Printf("[NEWS-POLLER] Ticker dynamically updated to %s", newDur)
			case <-ticker.C:
				if _, err := bot.RunNewsPollCycle(ctx); err != nil {
					log.Printf("[NEWS-POLLER] Error: %v", err)
				}
			}
		}
	}()

	<-ctx.Done()
	log.Printf("[SHUTDOWN] Shutting down Huginn gracefully...")
}

func emptyOrNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

func runCLIMode(ctx context.Context, nvd *cve.NVDClient, keyword, cveID, severity string, limit int) {
	items, total, err := nvd.Search(ctx, cve.SearchOptions{
		Keyword:  keyword,
		CVEID:    cveID,
		Severity: severity,
		Limit:    limit,
	})
	if err != nil {
		log.Fatalf("[ERROR] NVD query failed: %v", err)
	}
	fmt.Printf("=== Found %d total matches (showing %d) ===\n\n", total, len(items))

	for _, it := range items {
		kevBadge := ""
		if it.KEV != nil {
			kevBadge = " [🚨 CISA KEV ACTIVELY EXPLOITED]"
		}
		fmt.Printf("• %s | Score: %.1f (%s)%s\n  Published: %s\n  URL: %s\n  Summary: %s\n\n",
			it.ID, it.BaseScore, it.Severity, kevBadge,
			it.Published.Format("2006-01-02"), it.NVDURL(), it.Description)
	}
}
