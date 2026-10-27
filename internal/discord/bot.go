package discord

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"cve-discord-bot/internal/config"
	"cve-discord-bot/internal/cve"
	"cve-discord-bot/internal/news"
	"cve-discord-bot/internal/store"

	"github.com/bwmarrin/discordgo"
)

type Bot struct {
	cfg            *config.Config
	session        *discordgo.Session
	nvd            *cve.NVDClient
	kev            *cve.KEVClient
	news           *news.Client
	store          *store.Store
	webhook        *WebhookSender
	cmds           []*discordgo.ApplicationCommand
	cveIntervalCh  chan time.Duration
	newsIntervalCh chan time.Duration
}

func NewBot(cfg *config.Config, nvd *cve.NVDClient, kev *cve.KEVClient, st *store.Store, wh *WebhookSender) (*Bot, error) {
	b := &Bot{
		cfg:            cfg,
		nvd:            nvd,
		kev:            kev,
		news:           news.NewClient(),
		store:          st,
		webhook:        wh,
		cveIntervalCh:  make(chan time.Duration, 1),
		newsIntervalCh: make(chan time.Duration, 1),
	}
	if cfg.DiscordBotToken != "" {
		dg, err := discordgo.New("Bot " + cfg.DiscordBotToken)
		if err != nil {
			return nil, err
		}
		dg.Identify.Intents = discordgo.IntentsGuilds | discordgo.IntentsGuildMessages
		dg.AddHandler(b.onInteractionCreate)
		dg.AddHandler(b.onGuildCreate)
		b.session = dg
	}
	return b, nil
}

func (b *Bot) Start(ctx context.Context) error {
	if b.session == nil {
		log.Printf("[DISCORD] Running in Webhook-Only Poller Mode (DISCORD_BOT_TOKEN not set; Slash Commands disabled)")
		return nil
	}
	log.Printf("[DISCORD] Opening gateway WebSocket session...")
	if err := b.session.Open(); err != nil {
		return fmt.Errorf("open discord session: %w", err)
	}
	appID := b.cfg.DiscordAppID
	if appID == "" && b.session.State != nil && b.session.State.User != nil {
		appID = b.session.State.User.ID
	}

	log.Printf("[DISCORD] Connected as Bot AppID=%s. Waiting for GuildCreate events to instant-register /cve & /news...", appID)
	return nil
}

func (b *Bot) onGuildCreate(s *discordgo.Session, g *discordgo.GuildCreate) {
	if g.Guild == nil {
		return
	}
	appID := b.cfg.DiscordAppID
	if appID == "" && s.State != nil && s.State.User != nil {
		appID = s.State.User.ID
	}
	if err := b.registerCommands(appID, g.Guild.ID); err != nil {
		log.Printf("[DISCORD] WARN: Failed to register commands in guild %q (%s): %v", g.Guild.Name, g.Guild.ID, err)
	} else {
		log.Printf("[DISCORD] Registered /cve & /news slash commands in server %q (GuildID=%s)", g.Guild.Name, g.Guild.ID)
	}
}

func (b *Bot) Stop() {
	if b.session != nil {
		log.Printf("[DISCORD] Closing gateway WebSocket session...")
		_ = b.session.Close()
	}
}

func (b *Bot) CVEIntervalUpdates() <-chan time.Duration {
	return b.cveIntervalCh
}

func (b *Bot) NewsIntervalUpdates() <-chan time.Duration {
	return b.newsIntervalCh
}

func (b *Bot) registerCommands(appID, guildID string) error {
	minLimit := 1.0
	severityChoices := []*discordgo.ApplicationCommandOptionChoice{
		{Name: "CRITICAL (9.0 - 10.0)", Value: "CRITICAL"},
		{Name: "HIGH (7.0 - 8.9)", Value: "HIGH"},
		{Name: "MEDIUM (4.0 - 6.9)", Value: "MEDIUM"},
		{Name: "LOW (0.1 - 3.9)", Value: "LOW"},
	}
	newsCategoryChoices := []*discordgo.ApplicationCommandOptionChoice{
		{Name: "ALL Categories (Breaking + Research + Writeups)", Value: "all"},
		{Name: "🔥 Breaking Cybersec News (THN, BleepingComputer, DarkReading)", Value: "breaking"},
		{Name: "🔬 Zero-Day & Exploit Research (Project Zero, PortSwigger, watchTowr, ZDI)", Value: "research"},
		{Name: "🎯 Bug Bounty & Pentest Writeups (Intigriti)", Value: "writeups"},
	}

	cveCmd := &discordgo.ApplicationCommand{
		Name:        "cve",
		Description: "Search CVEs, inspect CISA KEV, and manage real-time CVE alerts",
		Options: []*discordgo.ApplicationCommandOption{
			{
				Type:        discordgo.ApplicationCommandOptionSubCommand,
				Name:        "search",
				Description: "Search CVEs by keyword and optional severity filter",
				Options: []*discordgo.ApplicationCommandOption{
					{
						Type:        discordgo.ApplicationCommandOptionString,
						Name:        "keyword",
						Description: "Product, vendor, or vulnerability keyword (e.g. openssh, fortinet, linux kernel)",
						Required:    true,
					},
					{
						Type:        discordgo.ApplicationCommandOptionString,
						Name:        "severity",
						Description: "Filter by CVSS v3 severity",
						Required:    false,
						Choices:     severityChoices,
					},
					{
						Type:        discordgo.ApplicationCommandOptionInteger,
						Name:        "limit",
						Description: "Number of results to display (1-10, default 3)",
						Required:    false,
						MinValue:    &minLimit,
						MaxValue:    10,
					},
					{
						Type:        discordgo.ApplicationCommandOptionBoolean,
						Name:        "push_webhook",
						Description: "Also push the search results to the configured Discord Webhook",
						Required:    false,
					},
				},
			},
			{
				Type:        discordgo.ApplicationCommandOptionSubCommand,
				Name:        "lookup",
				Description: "Look up full details for a specific CVE ID (e.g. CVE-2024-6387)",
				Options: []*discordgo.ApplicationCommandOption{
					{
						Type:        discordgo.ApplicationCommandOptionString,
						Name:        "id",
						Description: "CVE ID (e.g. CVE-2024-6387)",
						Required:    true,
					},
					{
						Type:        discordgo.ApplicationCommandOptionBoolean,
						Name:        "push_webhook",
						Description: "Also forward this CVE embed to the configured Discord Webhook",
						Required:    false,
					},
				},
			},
			{
				Type:        discordgo.ApplicationCommandOptionSubCommand,
				Name:        "kev",
				Description: "Show latest actively exploited vulnerabilities from CISA KEV catalog",
				Options: []*discordgo.ApplicationCommandOption{
					{
						Type:        discordgo.ApplicationCommandOptionString,
						Name:        "keyword",
						Description: "Optional vendor/product filter (e.g. ivanti, palo alto, microsoft)",
						Required:    false,
					},
					{
						Type:        discordgo.ApplicationCommandOptionInteger,
						Name:        "limit",
						Description: "Number of KEV entries (1-10, default 3)",
						Required:    false,
						MinValue:    &minLimit,
						MaxValue:    10,
					},
				},
			},
			{
				Type:        discordgo.ApplicationCommandOptionSubCommandGroup,
				Name:        "watch",
				Description: "Manage watched CVE severities and poll interval for this channel",
				Options: []*discordgo.ApplicationCommandOption{
					{
						Type:        discordgo.ApplicationCommandOptionSubCommand,
						Name:        "add",
						Description: "Watch a CVE severity and bind auto-alerts to this channel",
						Options: []*discordgo.ApplicationCommandOption{
							{
								Type:        discordgo.ApplicationCommandOptionString,
								Name:        "severity",
								Description: "Severity level to watch (CRITICAL, HIGH, MEDIUM, LOW)",
								Required:    true,
								Choices:     severityChoices,
							},
						},
					},
					{
						Type:        discordgo.ApplicationCommandOptionSubCommand,
						Name:        "remove",
						Description: "Remove a CVE severity level from the auto-tracker watchlist",
						Options: []*discordgo.ApplicationCommandOption{
							{
								Type:        discordgo.ApplicationCommandOptionString,
								Name:        "severity",
								Description: "Severity level to remove",
								Required:    true,
								Choices:     severityChoices,
							},
						},
					},
					{
						Type:        discordgo.ApplicationCommandOptionSubCommand,
						Name:        "interval",
						Description: "Set the CVE auto-poll interval (live reload without restart)",
						Options: []*discordgo.ApplicationCommandOption{
							{
								Type:        discordgo.ApplicationCommandOptionString,
								Name:        "duration",
								Description: "CVE poll interval (e.g. 5m, 15m, 30m, 1h, 6h — minimum 1m)",
								Required:    true,
							},
						},
					},
					{
						Type:        discordgo.ApplicationCommandOptionSubCommand,
						Name:        "list",
						Description: "List active watched severities and CVE tracker status",
					},
				},
			},
			{
				Type:        discordgo.ApplicationCommandOptionSubCommand,
				Name:        "poll-now",
				Description: "Trigger an immediate CVE poll cycle and push new alerts to Webhook/Channel",
			},
		},
	}

	newsCmd := &discordgo.ApplicationCommand{
		Name:        "news",
		Description: "Monitor cybersecurity news, zero-day research, and bug bounty writeups",
		Options: []*discordgo.ApplicationCommandOption{
			{
				Type:        discordgo.ApplicationCommandOptionSubCommand,
				Name:        "latest",
				Description: "Fetch latest cybersecurity news, research, or writeups",
				Options: []*discordgo.ApplicationCommandOption{
					{
						Type:        discordgo.ApplicationCommandOptionString,
						Name:        "category",
						Description: "Filter by feed category (default: ALL)",
						Required:    false,
						Choices:     newsCategoryChoices,
					},
					{
						Type:        discordgo.ApplicationCommandOptionInteger,
						Name:        "limit",
						Description: "Number of articles to display (1-10, default 3)",
						Required:    false,
						MinValue:    &minLimit,
						MaxValue:    10,
					},
				},
			},
			{
				Type:        discordgo.ApplicationCommandOptionSubCommand,
				Name:        "search",
				Description: "Search cybersecurity news and writeups by keyword or CVE",
				Options: []*discordgo.ApplicationCommandOption{
					{
						Type:        discordgo.ApplicationCommandOptionString,
						Name:        "keyword",
						Description: "Keyword, vendor, or CVE ID (e.g. ransomware, fortinet, cloudflare)",
						Required:    true,
					},
					{
						Type:        discordgo.ApplicationCommandOptionInteger,
						Name:        "limit",
						Description: "Number of articles to display (1-10, default 3)",
						Required:    false,
						MinValue:    &minLimit,
						MaxValue:    10,
					},
				},
			},
			{
				Type:        discordgo.ApplicationCommandOptionSubCommandGroup,
				Name:        "watch",
				Description: "Auto-post new cybersecurity news & writeups into this channel",
				Options: []*discordgo.ApplicationCommandOption{
					{
						Type:        discordgo.ApplicationCommandOptionSubCommand,
						Name:        "add",
						Description: "Subscribe this channel to cybersecurity news feeds",
						Options: []*discordgo.ApplicationCommandOption{
							{
								Type:        discordgo.ApplicationCommandOptionString,
								Name:        "category",
								Description: "Category to watch (defaults to ALL if omitted)",
								Required:    false,
								Choices:     newsCategoryChoices,
							},
						},
					},
					{
						Type:        discordgo.ApplicationCommandOptionSubCommand,
						Name:        "remove",
						Description: "Unsubscribe a news category from auto-alerts",
						Options: []*discordgo.ApplicationCommandOption{
							{
								Type:        discordgo.ApplicationCommandOptionString,
								Name:        "category",
								Description: "Category to remove (defaults to ALL if omitted)",
								Required:    false,
								Choices:     newsCategoryChoices,
							},
						},
					},
					{
						Type:        discordgo.ApplicationCommandOptionSubCommand,
						Name:        "interval",
						Description: "Set the News auto-poll interval (live reload without restart)",
						Options: []*discordgo.ApplicationCommandOption{
							{
								Type:        discordgo.ApplicationCommandOptionString,
								Name:        "duration",
								Description: "News poll interval (e.g. 5m, 15m, 30m, 1h, 6h — minimum 1m)",
								Required:    true,
							},
						},
					},
					{
						Type:        discordgo.ApplicationCommandOptionSubCommand,
						Name:        "list",
						Description: "Show watched news categories, interval, and bound channel status",
					},
				},
			},
			{
				Type:        discordgo.ApplicationCommandOptionSubCommand,
				Name:        "poll-now",
				Description: "Trigger an immediate news feed poll cycle and post new articles",
			},
		},
	}

	for _, cmd := range []*discordgo.ApplicationCommand{cveCmd, newsCmd} {
		created, err := b.session.ApplicationCommandCreate(appID, guildID, cmd)
		if err != nil {
			return err
		}
		b.cmds = append(b.cmds, created)
	}
	return nil
}

func (b *Bot) onInteractionCreate(s *discordgo.Session, i *discordgo.InteractionCreate) {
	if i.Type != discordgo.InteractionApplicationCommand {
		return
	}
	data := i.ApplicationCommandData()
	if len(data.Options) == 0 {
		return
	}

	user := "unknown"
	if i.Member != nil && i.Member.User != nil {
		user = fmt.Sprintf("%s (%s)", i.Member.User.Username, i.Member.User.ID)
	} else if i.User != nil {
		user = fmt.Sprintf("%s (%s)", i.User.Username, i.User.ID)
	}

	top := data.Options[0]
	subPath := "/" + data.Name + " " + top.Name
	if top.Type == discordgo.ApplicationCommandOptionSubCommandGroup && len(top.Options) > 0 {
		subPath += " " + top.Options[0].Name
	}
	log.Printf("[CMD] User=%s Channel=%s invoked %s", user, i.ChannelID, subPath)

	switch data.Name {
	case "cve":
		switch top.Name {
		case "search":
			b.handleSearch(s, i, top.Options)
		case "lookup":
			b.handleLookup(s, i, top.Options)
		case "kev":
			b.handleKEV(s, i, top.Options)
		case "watch":
			if len(top.Options) > 0 {
				b.handleWatch(s, i, top.Options[0])
			}
		case "poll-now":
			b.handlePollNow(s, i)
		}
	case "news":
		switch top.Name {
		case "latest":
			b.handleNewsLatest(s, i, top.Options)
		case "search":
			b.handleNewsSearch(s, i, top.Options)
		case "watch":
			if len(top.Options) > 0 {
				b.handleNewsWatch(s, i, top.Options[0])
			}
		case "poll-now":
			b.handleNewsPollNow(s, i)
		}
	}
}

func (b *Bot) handleSearch(s *discordgo.Session, i *discordgo.InteractionCreate, opts []*discordgo.ApplicationCommandInteractionDataOption) {
	_ = s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseDeferredChannelMessageWithSource,
	})

	var keyword, severity string
	limit := 3
	pushWebhook := false

	for _, o := range opts {
		switch o.Name {
		case "keyword":
			keyword = o.StringValue()
		case "severity":
			severity = o.StringValue()
		case "limit":
			limit = int(o.IntValue())
		case "push_webhook":
			pushWebhook = o.BoolValue()
		}
	}

	log.Printf("[CMD] /cve search keyword=%q severity=%q limit=%d push_webhook=%v", keyword, severity, limit, pushWebhook)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	items, total, err := b.nvd.Search(ctx, cve.SearchOptions{
		Keyword:  keyword,
		Severity: severity,
		Limit:    limit,
	})
	if err != nil {
		log.Printf("[CMD] /cve search error: %v", err)
		b.editDeferredError(s, i, fmt.Sprintf("❌ Failed to query NVD API: `%v`", err))
		return
	}
	if len(items) == 0 {
		log.Printf("[CMD] /cve search returned 0 results for keyword=%q", keyword)
		b.editDeferredError(s, i, fmt.Sprintf("🔍 No CVEs found matching keyword **`%s`** (severity: `%s`).", keyword, emptyDefault(severity, "ANY")))
		return
	}

	embeds := make([]*discordgo.MessageEmbed, 0, len(items))
	for _, item := range items {
		embeds = append(embeds, BuildCVEEmbed(item))
	}

	header := fmt.Sprintf("🔎 **CVE Search:** `%s` • Showing **%d** newest of **%d** total matches", keyword, len(embeds), total)
	if severity != "" {
		header += fmt.Sprintf(" • Severity: **%s**", severity)
	}

	if pushWebhook && b.webhook.Enabled() {
		if err := b.webhook.SendEmbeds(ctx, header, embeds); err != nil {
			header += fmt.Sprintf("\n⚠️ _Webhook push failed: %v_", err)
		} else {
			header += "\n✅ _Forwarded to Webhook_"
		}
	}

	_, _ = s.InteractionResponseEdit(i.Interaction, &discordgo.WebhookEdit{
		Content: &header,
		Embeds:  &embeds,
	})
	log.Printf("[CMD] /cve search delivered %d embed(s) (totalMatches=%d)", len(embeds), total)
}

func (b *Bot) handleLookup(s *discordgo.Session, i *discordgo.InteractionCreate, opts []*discordgo.ApplicationCommandInteractionDataOption) {
	_ = s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseDeferredChannelMessageWithSource,
	})

	var cveID string
	pushWebhook := false
	for _, o := range opts {
		switch o.Name {
		case "id":
			cveID = strings.ToUpper(strings.TrimSpace(o.StringValue()))
		case "push_webhook":
			pushWebhook = o.BoolValue()
		}
	}

	log.Printf("[CMD] /cve lookup id=%q push_webhook=%v", cveID, pushWebhook)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	items, _, err := b.nvd.Search(ctx, cve.SearchOptions{
		CVEID: cveID,
		Limit: 1,
	})
	if err != nil {
		log.Printf("[CMD] /cve lookup error for %s: %v", cveID, err)
		b.editDeferredError(s, i, fmt.Sprintf("❌ NVD lookup failed for `%s`: `%v`", cveID, err))
		return
	}
	if len(items) == 0 {
		log.Printf("[CMD] /cve lookup: %s not found", cveID)
		b.editDeferredError(s, i, fmt.Sprintf("🔍 CVE **`%s`** was not found in NVD.", cveID))
		return
	}

	embeds := []*discordgo.MessageEmbed{BuildCVEEmbed(items[0])}
	content := ""
	if pushWebhook && b.webhook.Enabled() {
		if err := b.webhook.SendEmbeds(ctx, fmt.Sprintf("📌 **CVE Lookup Shared:** `%s`", cveID), embeds); err != nil {
			content = fmt.Sprintf("⚠️ _Webhook push failed: %v_", err)
		} else {
			content = "✅ _Forwarded to Webhook_"
		}
	}

	_, _ = s.InteractionResponseEdit(i.Interaction, &discordgo.WebhookEdit{
		Content: &content,
		Embeds:  &embeds,
	})
	log.Printf("[CMD] /cve lookup delivered embed for %s (Score=%.1f %s)", items[0].ID, items[0].BaseScore, items[0].Severity)
}

func (b *Bot) handleKEV(s *discordgo.Session, i *discordgo.InteractionCreate, opts []*discordgo.ApplicationCommandInteractionDataOption) {
	_ = s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseDeferredChannelMessageWithSource,
	})

	var keyword string
	limit := 3
	for _, o := range opts {
		switch o.Name {
		case "keyword":
			keyword = o.StringValue()
		case "limit":
			limit = int(o.IntValue())
		}
	}

	log.Printf("[CMD] /cve kev keyword=%q limit=%d", keyword, limit)

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	entries, err := b.kev.Latest(ctx, limit, keyword)
	if err != nil {
		log.Printf("[CMD] /cve kev error: %v", err)
		b.editDeferredError(s, i, fmt.Sprintf("❌ Failed to load CISA KEV catalog: `%v`", err))
		return
	}
	if len(entries) == 0 {
		b.editDeferredError(s, i, fmt.Sprintf("🔍 No CISA KEV entries matched `%s`.", keyword))
		return
	}

	embeds := make([]*discordgo.MessageEmbed, 0, len(entries))
	for _, e := range entries {
		embeds = append(embeds, BuildKEVEmbed(e))
	}

	header := fmt.Sprintf("🚨 **CISA Known Exploited Vulnerabilities (KEV)** • Top **%d** newest entries", len(embeds))
	if keyword != "" {
		header += fmt.Sprintf(" matching `%s`", keyword)
	}
	_, _ = s.InteractionResponseEdit(i.Interaction, &discordgo.WebhookEdit{
		Content: &header,
		Embeds:  &embeds,
	})
	log.Printf("[CMD] /cve kev delivered %d KEV embed(s)", len(embeds))
}

func (b *Bot) handleWatch(s *discordgo.Session, i *discordgo.InteractionCreate, sub *discordgo.ApplicationCommandInteractionDataOption) {
	var msg string
	switch sub.Name {
	case "add":
		sev := strings.ToUpper(strings.TrimSpace(sub.Options[0].StringValue()))
		if err := b.store.AddSeverity(sev); err != nil {
			msg = fmt.Sprintf("❌ Failed to add severity: `%v`", err)
		} else {
			if i.ChannelID != "" {
				_ = b.store.SetAlertChannel(i.ChannelID)
			}
			active, _ := b.store.ListSeverities()
			chID := b.store.GetAlertChannel("")
			log.Printf("[CVE-WATCH] Added severity=%s boundChannel=%s activeSeverities=%v", sev, chID, active)
			msg = fmt.Sprintf("✅ Added **`%s`** to watched severities! (Active: `%s` • Alert Channel: <#%s>)", sev, strings.Join(active, "`, `"), chID)
		}
	case "remove":
		sev := strings.ToUpper(strings.TrimSpace(sub.Options[0].StringValue()))
		removed, err := b.store.RemoveSeverity(sev)
		if err != nil {
			msg = fmt.Sprintf("❌ Failed to remove severity: `%v`", err)
		} else if !removed {
			msg = fmt.Sprintf("⚠️ Severity **`%s`** was not in the watchlist.", sev)
		} else {
			active, _ := b.store.ListSeverities()
			log.Printf("[CVE-WATCH] Removed severity=%s activeSeverities=%v", sev, active)
			activeStr := "_None (auto-alerts paused)_"
			if len(active) > 0 {
				activeStr = "`" + strings.Join(active, "`, `") + "`"
			}
			msg = fmt.Sprintf("🗑️ Removed **`%s`** from watched severities. (Active: %s)", sev, activeStr)
		}
	case "interval":
		raw := strings.ToLower(strings.TrimSpace(sub.Options[0].StringValue()))
		if _, err := fmt.Sscanf(raw, "%d", new(int)); err == nil && !strings.ContainsAny(raw, "smhd") {
			raw += "m"
		}
		d, err := time.ParseDuration(raw)
		if err != nil || d < time.Minute {
			msg = "❌ Invalid duration! Use a format like `5m`, `15m`, `30m`, `1h`, or `6h` (minimum `1m`)."
		} else if err := b.store.SetPollInterval(d); err != nil {
			msg = fmt.Sprintf("❌ Failed to save CVE poll interval: `%v`", err)
		} else {
			pushDuration(b.cveIntervalCh, d)
			log.Printf("[CVE-WATCH] Updated CVE poll interval to %s", d)
			msg = fmt.Sprintf("⏱️ **CVE** poll interval updated to **`%s`** (live-reloaded immediately)!", d)
		}
	case "list":
		sevs, _ := b.store.ListSeverities()
		sevDisplay := "_None (auto-alerts paused — use `/cve watch add` to add a severity)_"
		if len(sevs) > 0 {
			sevDisplay = "`" + strings.Join(sevs, "`, `") + "`"
		}
		whStatus := "❌ Not set"
		if b.webhook.Enabled() {
			whStatus = "✅ Configured"
		}
		chStatus := "❌ Not set"
		if chID := b.store.GetAlertChannel(""); chID != "" {
			chStatus = fmt.Sprintf("<#%s>", chID)
		}
		curInterval := b.store.GetPollInterval(b.cfg.DefaultCVEPollInterval)
		msg = fmt.Sprintf(
			"📡 **Huginn CVE Auto-Tracker Configuration**\n"+
				"• **Watched Severities:** %s\n"+
				"• **CVE Poll Interval:** `%s`\n"+
				"• **Webhook Output:** %s\n"+
				"• **CVE Alert Channel:** %s\n"+
				"• **Tracked CVEs in DB:** `%d`",
			sevDisplay, curInterval, whStatus, chStatus, b.store.SeenCount(),
		)
	}

	_ = s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Content: msg,
		},
	})
}

func (b *Bot) handlePollNow(s *discordgo.Session, i *discordgo.InteractionCreate) {
	_ = s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseDeferredChannelMessageWithSource,
	})

	if b.store.GetAlertChannel("") == "" && i.ChannelID != "" {
		_ = b.store.SetAlertChannel(i.ChannelID)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	sent, err := b.RunPollCycle(ctx)
	var content string
	if err != nil {
		content = fmt.Sprintf("⚠️ CVE poll cycle finished with error: `%v` (Alerts dispatched: **%d**)", err, sent)
	} else {
		content = fmt.Sprintf("✅ Manual CVE poll cycle complete! Dispatched **%d** new CVE alert(s).", sent)
	}
	_, _ = s.InteractionResponseEdit(i.Interaction, &discordgo.WebhookEdit{
		Content: &content,
	})
}

// ==========================================
// /news Handlers
// ==========================================

func (b *Bot) handleNewsLatest(s *discordgo.Session, i *discordgo.InteractionCreate, opts []*discordgo.ApplicationCommandInteractionDataOption) {
	_ = s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseDeferredChannelMessageWithSource,
	})

	category := "all"
	limit := 3
	for _, o := range opts {
		switch o.Name {
		case "category":
			category = o.StringValue()
		case "limit":
			limit = int(o.IntValue())
		}
	}

	log.Printf("[CMD] /news latest category=%q limit=%d", category, limit)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	_ = b.kev.EnsureLoaded(ctx)
	articles, err := b.news.Fetch(ctx, []string{category}, "", limit)
	if err != nil {
		log.Printf("[CMD] /news latest error: %v", err)
		b.editDeferredError(s, i, fmt.Sprintf("❌ Failed to fetch cybersecurity feeds: `%v`", err))
		return
	}
	if len(articles) == 0 {
		b.editDeferredError(s, i, "🔍 No recent cybersecurity articles found for that category.")
		return
	}

	embeds := make([]*discordgo.MessageEmbed, 0, len(articles))
	for _, art := range articles {
		embeds = append(embeds, BuildNewsEmbed(art, b.kev))
	}

	header := fmt.Sprintf("📰 **Latest Cybersecurity Intel** • Category: **`%s`** (Showing **%d** newest)", strings.ToUpper(category), len(embeds))
	_, _ = s.InteractionResponseEdit(i.Interaction, &discordgo.WebhookEdit{
		Content: &header,
		Embeds:  &embeds,
	})
	log.Printf("[CMD] /news latest delivered %d article embed(s)", len(embeds))
}

func (b *Bot) handleNewsSearch(s *discordgo.Session, i *discordgo.InteractionCreate, opts []*discordgo.ApplicationCommandInteractionDataOption) {
	_ = s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseDeferredChannelMessageWithSource,
	})

	var keyword string
	limit := 3
	for _, o := range opts {
		switch o.Name {
		case "keyword":
			keyword = o.StringValue()
		case "limit":
			limit = int(o.IntValue())
		}
	}

	log.Printf("[CMD] /news search keyword=%q limit=%d", keyword, limit)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	_ = b.kev.EnsureLoaded(ctx)
	articles, err := b.news.Fetch(ctx, nil, keyword, limit)
	if err != nil {
		log.Printf("[CMD] /news search error: %v", err)
		b.editDeferredError(s, i, fmt.Sprintf("❌ Failed to search news feeds: `%v`", err))
		return
	}
	if len(articles) == 0 {
		log.Printf("[CMD] /news search: 0 articles matched %q", keyword)
		b.editDeferredError(s, i, fmt.Sprintf("🔍 No articles found matching **`%s`** across active RSS feeds.", keyword))
		return
	}

	embeds := make([]*discordgo.MessageEmbed, 0, len(articles))
	for _, art := range articles {
		embeds = append(embeds, BuildNewsEmbed(art, b.kev))
	}

	header := fmt.Sprintf("🔎 **Cybersec News Search:** `%s` • Found **%d** matching article(s)", keyword, len(embeds))
	_, _ = s.InteractionResponseEdit(i.Interaction, &discordgo.WebhookEdit{
		Content: &header,
		Embeds:  &embeds,
	})
	log.Printf("[CMD] /news search delivered %d article embed(s) for keyword=%q", len(embeds), keyword)
}

func (b *Bot) handleNewsWatch(s *discordgo.Session, i *discordgo.InteractionCreate, sub *discordgo.ApplicationCommandInteractionDataOption) {
	var msg string
	switch sub.Name {
	case "add":
		cat := "all"
		if len(sub.Options) > 0 && sub.Options[0].StringValue() != "" {
			cat = strings.ToLower(strings.TrimSpace(sub.Options[0].StringValue()))
		}
		if err := b.store.AddNewsCategory(cat); err != nil {
			msg = fmt.Sprintf("❌ Failed to add news category: `%v`", err)
		} else {
			if i.ChannelID != "" {
				_ = b.store.SetNewsAlertChannel(i.ChannelID)
			}
			active, _ := b.store.ListNewsCategories()
			chID := b.store.GetNewsAlertChannel("")
			log.Printf("[NEWS-WATCH] Added category=%s boundChannel=%s activeCategories=%v", cat, chID, active)
			msg = fmt.Sprintf("📰 Subscribed <#%s> to cybersecurity news feeds! (Active Categories: `%s`)", chID, strings.Join(active, "`, `"))
		}
	case "remove":
		cat := "all"
		if len(sub.Options) > 0 && sub.Options[0].StringValue() != "" {
			cat = strings.ToLower(strings.TrimSpace(sub.Options[0].StringValue()))
		}
		removed, err := b.store.RemoveNewsCategory(cat)
		if err != nil {
			msg = fmt.Sprintf("❌ Failed to remove news category: `%v`", err)
		} else if !removed {
			msg = fmt.Sprintf("⚠️ Category **`%s`** was not in the news watchlist.", cat)
		} else {
			active, _ := b.store.ListNewsCategories()
			log.Printf("[NEWS-WATCH] Removed category=%s activeCategories=%v", cat, active)
			activeStr := "_None (news auto-alerts paused)_"
			if len(active) > 0 {
				activeStr = "`" + strings.Join(active, "`, `") + "`"
			}
			msg = fmt.Sprintf("🗑️ Removed **`%s`** from news watchlist. (Active: %s)", cat, activeStr)
		}
	case "interval":
		raw := strings.ToLower(strings.TrimSpace(sub.Options[0].StringValue()))
		if _, err := fmt.Sscanf(raw, "%d", new(int)); err == nil && !strings.ContainsAny(raw, "smhd") {
			raw += "m"
		}
		d, err := time.ParseDuration(raw)
		if err != nil || d < time.Minute {
			msg = "❌ Invalid duration! Use a format like `5m`, `15m`, `30m`, `1h`, or `6h` (minimum `1m`)."
		} else if err := b.store.SetNewsPollInterval(d); err != nil {
			msg = fmt.Sprintf("❌ Failed to save News poll interval: `%v`", err)
		} else {
			pushDuration(b.newsIntervalCh, d)
			log.Printf("[NEWS-WATCH] Updated News poll interval to %s", d)
			msg = fmt.Sprintf("⏱️ **News** poll interval updated to **`%s`** (live-reloaded immediately)!", d)
		}
	case "list":
		cats, _ := b.store.ListNewsCategories()
		catDisplay := "_None (run `/news watch add` in the channel where you want news posted)_"
		if len(cats) > 0 {
			catDisplay = "`" + strings.Join(cats, "`, `") + "`"
		}
		chStatus := "❌ Not set"
		if chID := b.store.GetNewsAlertChannel(""); chID != "" {
			chStatus = fmt.Sprintf("<#%s>", chID)
		}
		curInterval := b.store.GetNewsPollInterval(b.cfg.DefaultNewsPollInterval)
		msg = fmt.Sprintf(
			"📰 **Huginn Cybersec News Radar Configuration**\n"+
				"• **Watched Categories:** %s\n"+
				"• **News Poll Interval:** `%s`\n"+
				"• **News Alert Channel:** %s\n"+
				"• **Sources:** `The Hacker News`, `BleepingComputer`, `Dark Reading`, `PortSwigger Research`, `Project Zero`, `watchTowr Labs`, `ZDI`, `Intigriti`\n"+
				"• **Tracked Articles in DB:** `%d`",
			catDisplay, curInterval, chStatus, b.store.SeenNewsCount(),
		)
	}

	_ = s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Content: msg,
		},
	})
}

func (b *Bot) handleNewsPollNow(s *discordgo.Session, i *discordgo.InteractionCreate) {
	_ = s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseDeferredChannelMessageWithSource,
	})

	if b.store.GetNewsAlertChannel("") == "" && i.ChannelID != "" {
		_ = b.store.SetNewsAlertChannel(i.ChannelID)
	}
	if cats, _ := b.store.ListNewsCategories(); len(cats) == 0 {
		_ = b.store.AddNewsCategory("all")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()

	sent, err := b.RunNewsPollCycle(ctx)
	var content string
	if err != nil {
		content = fmt.Sprintf("⚠️ News poll finished with error: `%v` (Articles dispatched: **%d**)", err, sent)
	} else {
		content = fmt.Sprintf("✅ Manual news poll complete! Dispatched **%d** new cybersecurity article(s).", sent)
	}
	_, _ = s.InteractionResponseEdit(i.Interaction, &discordgo.WebhookEdit{
		Content: &content,
	})
}

// ==========================================
// Background Poll Cycles (CVE & News)
// ==========================================

func (b *Bot) RunPollCycle(ctx context.Context) (int, error) {
	cycleStart := time.Now()
	watchedSevs, _ := b.store.ListSeverities()
	alertChannelID := b.store.GetAlertChannel("")

	if len(watchedSevs) == 0 {
		log.Printf("[CVE-POLL] Skipped: no severities watched (use /cve watch add)")
		return 0, nil
	}
	if alertChannelID == "" && !b.webhook.Enabled() {
		log.Printf("[CVE-POLL] Skipped: no alert channel or webhook bound yet (run /cve watch add in a Discord channel)")
		return 0, nil
	}

	now := time.Now().UTC()
	start := now.Add(-time.Duration(b.cfg.LookbackHours) * time.Hour)
	log.Printf("[CVE-POLL] Starting cycle (window=%dh, watchedSeverities=%v, channel=%s, webhook=%v)",
		b.cfg.LookbackHours, watchedSevs, emptyDefault(alertChannelID, "none"), b.webhook.Enabled())

	items, total, err := b.nvd.Search(ctx, cve.SearchOptions{
		PubStartDate: &start,
		PubEndDate:   &now,
		Limit:        100,
	})
	if err != nil {
		return 0, err
	}

	var (
		matched     []cve.CVEItem
		skippedSeen int
		skippedSev  int
	)
	for _, item := range items {
		if b.store.IsSeen(item.ID) {
			skippedSeen++
			continue
		}
		if item.KEV == nil && !b.store.IsSeverityWatched(item.Severity) {
			skippedSev++
			continue
		}
		matched = append(matched, item)
	}

	log.Printf("[CVE-POLL] Evaluated %d tail CVEs (24h total=%d): %d new matched, %d already seen, %d filtered by severity",
		len(items), total, len(matched), skippedSeen, skippedSev)

	if len(matched) == 0 {
		log.Printf("[CVE-POLL] Cycle finished in %s (0 new CVEs to dispatch)", time.Since(cycleStart).Round(time.Millisecond))
		return 0, nil
	}

	embeds := make([]*discordgo.MessageEmbed, 0, len(matched))
	for _, m := range matched {
		embeds = append(embeds, BuildCVEEmbed(m))
	}

	header := fmt.Sprintf("🚨 **New CVE Security Alert** (%d new • Watched Severities: `%s`)", len(matched), strings.Join(watchedSevs, ", "))
	dispatched := false

	if b.webhook != nil && b.webhook.Enabled() {
		log.Printf("[CVE-POLL] Pushing %d CVE embed(s) to Discord Webhook...", len(embeds))
		if err := b.webhook.SendEmbeds(ctx, header, embeds); err != nil {
			return 0, fmt.Errorf("webhook dispatch: %w", err)
		}
		dispatched = true
	}

	if b.session != nil && alertChannelID != "" {
		for idx, emb := range embeds {
			m := matched[idx]
			log.Printf("[CVE-POLL] Sending %s (CVSS %.1f %s) to channel %s (%d/%d)...", m.ID, m.BaseScore, m.Severity, alertChannelID, idx+1, len(embeds))
			msg := &discordgo.MessageSend{Embeds: []*discordgo.MessageEmbed{emb}}
			if idx == 0 {
				msg.Content = header
			}
			if _, err := b.session.ChannelMessageSendComplex(alertChannelID, msg); err != nil {
				log.Printf("[CVE-POLL] WARN: Failed sending %s to channel %s: %v", m.ID, alertChannelID, err)
			} else {
				dispatched = true
			}
		}
	}

	if dispatched {
		for _, m := range matched {
			_ = b.store.MarkSeen(m.ID, m.Severity)
		}
	}

	log.Printf("[CVE-POLL] Cycle finished in %s: dispatched %d new CVE alert(s) (totalSeenInDB=%d)",
		time.Since(cycleStart).Round(time.Millisecond), len(matched), b.store.SeenCount())
	return len(matched), nil
}

func (b *Bot) RunNewsPollCycle(ctx context.Context) (int, error) {
	cycleStart := time.Now()
	cats, _ := b.store.ListNewsCategories()
	newsChannelID := b.store.GetNewsAlertChannel("")

	if len(cats) == 0 {
		log.Printf("[NEWS-POLL] Skipped: no news categories watched (run /news watch add in a Discord channel)")
		return 0, nil
	}
	if newsChannelID == "" && !b.webhook.Enabled() {
		log.Printf("[NEWS-POLL] Skipped: no news alert channel bound yet (run /news watch add in a Discord channel)")
		return 0, nil
	}

	log.Printf("[NEWS-POLL] Starting cycle (categories=%v, channel=%s)", cats, emptyDefault(newsChannelID, "webhook"))

	_ = b.kev.EnsureLoaded(ctx)
	articles, err := b.news.Fetch(ctx, cats, "", 40)
	if err != nil {
		return 0, err
	}

	isFirstSeed := b.store.SeenNewsCount() == 0
	var (
		unseen      []news.Article
		skippedSeen int
	)
	for _, art := range articles {
		if b.store.IsNewsSeen(art.URL) {
			skippedSeen++
			continue
		}
		unseen = append(unseen, art)
	}

	log.Printf("[NEWS-POLL] Evaluated %d articles: %d unseen, %d already seen in DB", len(articles), len(unseen), skippedSeen)

	if len(unseen) == 0 {
		log.Printf("[NEWS-POLL] Cycle finished in %s (0 new articles to dispatch)", time.Since(cycleStart).Round(time.Millisecond))
		return 0, nil
	}

	toSend := unseen
	var backlog []news.Article
	if isFirstSeed && len(unseen) > 5 {
		toSend = unseen[:5]
		backlog = unseen[5:]
		log.Printf("[NEWS-POLL] Initial seed detected: sending 5 newest articles and marking %d older backlog articles as seen", len(backlog))
	} else if len(unseen) > 10 {
		toSend = unseen[:10]
	}

	embeds := make([]*discordgo.MessageEmbed, 0, len(toSend))
	for _, art := range toSend {
		embeds = append(embeds, BuildNewsEmbed(art, b.kev))
	}

	header := fmt.Sprintf("📰 **New Cybersecurity Intel** (%d new article(s) • Categories: `%s`)", len(embeds), strings.Join(cats, ", "))
	dispatched := false

	if b.session != nil && newsChannelID != "" {
		for idx, emb := range embeds {
			art := toSend[idx]
			log.Printf("[NEWS-POLL] Sending [%s] %q to channel %s (%d/%d)...", art.Source, art.Title, newsChannelID, idx+1, len(embeds))
			msg := &discordgo.MessageSend{Embeds: []*discordgo.MessageEmbed{emb}}
			if idx == 0 {
				msg.Content = header
			}
			if _, err := b.session.ChannelMessageSendComplex(newsChannelID, msg); err != nil {
				log.Printf("[NEWS-POLL] WARN: Failed sending article to channel %s: %v", newsChannelID, err)
			} else {
				dispatched = true
			}
		}
	} else if b.webhook != nil && b.webhook.Enabled() {
		log.Printf("[NEWS-POLL] Pushing %d article embed(s) to Discord Webhook...", len(embeds))
		if err := b.webhook.SendEmbeds(ctx, header, embeds); err != nil {
			return 0, fmt.Errorf("news webhook dispatch: %w", err)
		}
		dispatched = true
	}

	if dispatched {
		for _, art := range toSend {
			_ = b.store.MarkNewsSeen(art.URL, art.Source)
		}
		for _, art := range backlog {
			_ = b.store.MarkNewsSeen(art.URL, art.Source)
		}
	}

	log.Printf("[NEWS-POLL] Cycle finished in %s: dispatched %d new article(s) (totalSeenNewsInDB=%d)",
		time.Since(cycleStart).Round(time.Millisecond), len(toSend), b.store.SeenNewsCount())
	return len(toSend), nil
}

func pushDuration(ch chan time.Duration, d time.Duration) {
	select {
	case ch <- d:
	default:
		select {
		case <-ch:
		default:
		}
		ch <- d
	}
}

func (b *Bot) editDeferredError(s *discordgo.Session, i *discordgo.InteractionCreate, msg string) {
	_, _ = s.InteractionResponseEdit(i.Interaction, &discordgo.WebhookEdit{
		Content: &msg,
	})
}

func emptyDefault(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}
