package config

import (
	"os"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	DiscordBotToken   string
	DiscordAppID      string
	DiscordWebhookURL string
	NVDAPIKey         string
	DBPath            string

	DefaultCVEPollInterval  time.Duration
	DefaultNewsPollInterval time.Duration
	LookbackHours           int
}

func Load() *Config {
	_ = godotenv.Load()

	dbPath := strings.TrimSpace(os.Getenv("DB_PATH"))
	if dbPath == "" {
		dbPath = "./cve_tracker.db"
	}

	return &Config{
		DiscordBotToken:         strings.TrimSpace(os.Getenv("DISCORD_BOT_TOKEN")),
		DiscordAppID:            strings.TrimSpace(os.Getenv("DISCORD_APP_ID")),
		DiscordWebhookURL:       strings.TrimSpace(os.Getenv("DISCORD_WEBHOOK_URL")),
		NVDAPIKey:               strings.TrimSpace(os.Getenv("NVD_API_KEY")),
		DBPath:                  dbPath,
		DefaultCVEPollInterval:  15 * time.Minute,
		DefaultNewsPollInterval: 15 * time.Minute,
		LookbackHours:           24,
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
