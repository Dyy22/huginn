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

	"github.com/bwmarrin/discordgo"
)

func main() {
	var (
		cliSearch      = flag.String("search", "", "CLI test: Search CVEs by keyword and print/webhook results without starting the bot daemon")
		cliCVE         = flag.String("cve", "", "CLI test: Lookup a specific CVE ID (e.g. CVE-2024-6387)")
		cliSeverity    = flag.String("severity", "", "CLI test: Filter by CVSS v3 severity (LOW, MEDIUM, HIGH, CRITICAL)")
		cliLimit       = flag.Int("limit", 3, "CLI test: Max results to fetch (default 3)")
		cliSendWebhook = flag.Bool("send-webhook", false, "CLI test: Push the fetched CLI results directly to DISCORD_WEBHOOK_URL")
	)
	flag.Parse()

	cfg := config.Load()
	kevClient := cve.NewKEVClient()
	nvdClient := cve.NewNVDClient(cfg.NVDAPIKey, kevClient)
	webhook := discord.NewWebhookSender(cfg.DiscordWebhookURL)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// One-shot CLI mode for testing NVD + KEV + Webhook without needing Bot daemon
	if *cliSearch != "" || *cliCVE != "" {
		runCLIMode(ctx, nvdClient, webhook, *cliSearch, *cliCVE, *cliSeverity, *cliLimit, *cliSendWebhook)
		return
	}

	st, err := store.Open(cfg.DBPath, cfg.DefaultWatch, cfg.MinSeverity)
	if err != nil {
		log.Fatalf("[FATAL] Failed to open SQLite store (%s): %v", cfg.DBPath, err)
	}
	defer st.Close()

	log.Printf("[INFO] Preloading CISA KEV catalog...")
	if err := kevClient.EnsureLoaded(ctx); err != nil {
		log.Printf("[WARN] Initial CISA KEV fetch failed (will retry): %v", err)
	}

	if cfg.DiscordBotToken == "" && !webhook.Enabled() {
		log.Fatalf("[FATAL] Neither DISCORD_BOT_TOKEN nor DISCORD_WEBHOOK_URL is configured. Set at least one in .env or run CLI mode: ./cvebot -search openssh")
	}

	bot, err := discord.NewBot(cfg, nvdClient, kevClient, st, webhook)
	if err != nil {
		log.Fatalf("[FATAL] Failed to initialize Discord bot: %v", err)
	}

	if err := bot.Start(ctx); err != nil {
		log.Fatalf("[FATAL] Failed to start Discord bot: %v", err)
	}
	defer bot.Stop()

	sevs, _ := st.ListSeverities()
	curInterval := st.GetPollInterval(cfg.PollInterval)
	log.Printf("[INFO] Bot is online! Polling NVD + CISA KEV every %s (WatchedSeverities=%v)", curInterval, sevs)

	// Background poller loop with live interval reload
	go func() {
		ticker := time.NewTicker(curInterval)
		defer ticker.Stop()

		// Initial poll after 10 seconds
		select {
		case <-ctx.Done():
			return
		case newDur := <-bot.IntervalUpdates():
			ticker.Reset(newDur)
			log.Printf("[INFO] Poll ticker dynamically updated to %s", newDur)
		case <-time.After(10 * time.Second):
			if n, err := bot.RunPollCycle(ctx); err != nil {
				log.Printf("[WARN] Poll cycle error: %v", err)
			} else {
				log.Printf("[INFO] Poll cycle complete: %d new CVE alert(s) dispatched", n)
			}
		}

		for {
			select {
			case <-ctx.Done():
				return
			case newDur := <-bot.IntervalUpdates():
				ticker.Reset(newDur)
				log.Printf("[INFO] Poll ticker dynamically updated to %s", newDur)
			case <-ticker.C:
				if n, err := bot.RunPollCycle(ctx); err != nil {
					log.Printf("[WARN] Poll cycle error: %v", err)
				} else {
					log.Printf("[INFO] Poll cycle complete: %d new CVE alert(s) dispatched", n)
				}
			}
		}
	}()

	<-ctx.Done()
	log.Printf("[INFO] Shutting down CVE Discord Bot gracefully...")
}

func runCLIMode(ctx context.Context, nvd *cve.NVDClient, wh *discord.WebhookSender, keyword, cveID, severity string, limit int, sendWebhook bool) {
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

	var embeds []*discordgo.MessageEmbed
	for _, it := range items {
		kevBadge := ""
		if it.KEV != nil {
			kevBadge = " [🚨 CISA KEV ACTIVELY EXPLOITED]"
		}
		fmt.Printf("• %s | Score: %.1f (%s)%s\n  Published: %s\n  URL: %s\n  Summary: %s\n\n",
			it.ID, it.BaseScore, it.Severity, kevBadge,
			it.Published.Format("2006-01-02"), it.NVDURL(), it.Description)
		embeds = append(embeds, discord.BuildCVEEmbed(it))
	}

	if sendWebhook {
		if !wh.Enabled() {
			log.Fatalf("[ERROR] -send-webhook requested, but DISCORD_WEBHOOK_URL is not set in .env")
		}
		header := fmt.Sprintf("🔎 **CLI CVE Push** (`%s%s`)", keyword, cveID)
		if err := wh.SendEmbeds(ctx, header, embeds); err != nil {
			log.Fatalf("[ERROR] Webhook send failed: %v", err)
		}
		fmt.Printf("✅ Successfully pushed %d Rich Embed(s) to Discord Webhook!\n", len(embeds))
	}
}
