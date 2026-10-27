package store

import (
	"database/sql"
	"strings"
	"time"

	"cve-discord-bot/internal/config"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

func Open(path string, _ []string, defaultMinSeverity string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)

	schema := `
	CREATE TABLE IF NOT EXISTS seen_cves (
		cve_id TEXT PRIMARY KEY,
		severity TEXT NOT NULL,
		notified_at DATETIME NOT NULL
	);
	CREATE TABLE IF NOT EXISTS watched_severities (
		severity TEXT PRIMARY KEY,
		added_at DATETIME NOT NULL
	);
	CREATE TABLE IF NOT EXISTS settings (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL
	);
	`
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, err
	}

	s := &Store{db: db}

	// Seed default watched severities once based on defaultMinSeverity
	var seeded string
	_ = db.QueryRow(`SELECT value FROM settings WHERE key = 'severities_seeded'`).Scan(&seeded)
	if seeded == "" && defaultMinSeverity != "" {
		minRank := config.SeverityRank(defaultMinSeverity)
		for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
			if config.SeverityRank(sev) >= minRank {
				_ = s.AddSeverity(sev)
			}
		}
		_, _ = db.Exec(`INSERT OR REPLACE INTO settings (key, value) VALUES ('severities_seeded', '1')`)
	}

	return s, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) IsSeen(cveID string) bool {
	var id string
	err := s.db.QueryRow(`SELECT cve_id FROM seen_cves WHERE cve_id = ?`, strings.ToUpper(strings.TrimSpace(cveID))).Scan(&id)
	return err == nil
}

func (s *Store) MarkSeen(cveID, severity string) error {
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO seen_cves (cve_id, severity, notified_at) VALUES (?, ?, ?)`,
		strings.ToUpper(strings.TrimSpace(cveID)),
		strings.ToUpper(strings.TrimSpace(severity)),
		time.Now().UTC(),
	)
	return err
}

func (s *Store) SeenCount() int {
	var count int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM seen_cves`).Scan(&count)
	return count
}

func (s *Store) AddSeverity(sev string) error {
	sev = strings.ToUpper(strings.TrimSpace(sev))
	if sev == "" {
		return nil
	}
	_, err := s.db.Exec(
		`INSERT OR IGNORE INTO watched_severities (severity, added_at) VALUES (?, ?)`,
		sev,
		time.Now().UTC(),
	)
	return err
}

func (s *Store) RemoveSeverity(sev string) (bool, error) {
	sev = strings.ToUpper(strings.TrimSpace(sev))
	res, err := s.db.Exec(`DELETE FROM watched_severities WHERE severity = ?`, sev)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (s *Store) ListSeverities() ([]string, error) {
	rows, err := s.db.Query(`SELECT severity FROM watched_severities`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	active := make(map[string]bool)
	for rows.Next() {
		var sev string
		if err := rows.Scan(&sev); err == nil {
			active[strings.ToUpper(strings.TrimSpace(sev))] = true
		}
	}

	// Order highest to lowest
	var ordered []string
	for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
		if active[sev] {
			ordered = append(ordered, sev)
		}
	}
	return ordered, nil
}

func (s *Store) IsSeverityWatched(sev string) bool {
	sev = strings.ToUpper(strings.TrimSpace(sev))
	var out string
	err := s.db.QueryRow(`SELECT severity FROM watched_severities WHERE severity = ?`, sev).Scan(&out)
	return err == nil
}

func (s *Store) GetAlertChannel(fallback string) string {
	var val string
	err := s.db.QueryRow(`SELECT value FROM settings WHERE key = 'alert_channel_id'`).Scan(&val)
	if err != nil || strings.TrimSpace(val) == "" {
		return strings.TrimSpace(fallback)
	}
	return strings.TrimSpace(val)
}

func (s *Store) SetAlertChannel(channelID string) error {
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO settings (key, value) VALUES ('alert_channel_id', ?)`,
		strings.TrimSpace(channelID),
	)
	return err
}

func (s *Store) GetPollInterval(fallback time.Duration) time.Duration {
	var val string
	err := s.db.QueryRow(`SELECT value FROM settings WHERE key = 'poll_interval'`).Scan(&val)
	if err != nil || strings.TrimSpace(val) == "" {
		return fallback
	}
	if d, err := time.ParseDuration(strings.TrimSpace(val)); err == nil && d >= time.Minute {
		return d
	}
	return fallback
}

func (s *Store) SetPollInterval(d time.Duration) error {
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO settings (key, value) VALUES ('poll_interval', ?)`,
		d.String(),
	)
	return err
}
