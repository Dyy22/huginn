package config

import (
	"os"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	DiscordBotToken       string
	DiscordAppID          string
	DiscordGuildID        string
	DiscordWebhookURL     string
	DiscordAlertChannelID string

	NVDAPIKey     string
	PollInterval  time.Duration
	MinSeverity   string
	DefaultWatch  []string
	DBPath        string
	LookbackHours int
}

func Load() *Config {
	_ = godotenv.Load()

	pollInterval := 15 * time.Minute
	if v := os.Getenv("POLL_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d >= time.Minute {
			pollInterval = d
		}
	}

	minSev := strings.ToUpper(strings.TrimSpace(os.Getenv("MIN_SEVERITY")))
	if minSev == "" {
		minSev = "HIGH"
	}

	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "./cve_tracker.db"
	}

	var watchlist []string
	if raw := os.Getenv("WATCH_KEYWORDS"); raw != "" {
		for _, kw := range strings.Split(raw, ",") {
			kw = strings.TrimSpace(kw)
			if kw != "" {
				watchlist = append(watchlist, kw)
			}
		}
	}

	return &Config{
		DiscordBotToken:       strings.TrimSpace(os.Getenv("DISCORD_BOT_TOKEN")),
		DiscordAppID:          strings.TrimSpace(os.Getenv("DISCORD_APP_ID")),
		DiscordGuildID:        strings.TrimSpace(os.Getenv("DISCORD_GUILD_ID")),
		DiscordWebhookURL:     strings.TrimSpace(os.Getenv("DISCORD_WEBHOOK_URL")),
		DiscordAlertChannelID: strings.TrimSpace(os.Getenv("DISCORD_ALERT_CHANNEL_ID")),
		NVDAPIKey:             strings.TrimSpace(os.Getenv("NVD_API_KEY")),
		PollInterval:          pollInterval,
		MinSeverity:           minSev,
		DefaultWatch:          watchlist,
		DBPath:                dbPath,
		LookbackHours:         24,
	}
}

func SeverityRank(sev string) int {
	switch strings.ToUpper(strings.TrimSpace(sev)) {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}
