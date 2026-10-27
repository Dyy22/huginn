package cve

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

const cisaKEVFeedURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

type cisaKEVFeed struct {
	Title           string     `json:"title"`
	CatalogVersion  string     `json:"catalogVersion"`
	DateReleased    string     `json:"dateReleased"`
	Count           int        `json:"count"`
	Vulnerabilities []KEVEntry `json:"vulnerabilities"`
}

type KEVClient struct {
	httpClient *http.Client
	mu         sync.RWMutex
	byID       map[string]KEVEntry
	list       []KEVEntry
	lastFetch  time.Time
}

func NewKEVClient() *KEVClient {
	return &KEVClient{
		httpClient: &http.Client{Timeout: 25 * time.Second},
		byID:       make(map[string]KEVEntry),
	}
}

func (k *KEVClient) EnsureLoaded(ctx context.Context) error {
	k.mu.RLock()
	fresh := time.Since(k.lastFetch) < 2*time.Hour && len(k.byID) > 0
	k.mu.RUnlock()
	if fresh {
		return nil
	}
	return k.Refresh(ctx)
}

func (k *KEVClient) Refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cisaKEVFeedURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "CVE-Discord-Tracker/1.0")

	resp, err := k.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("fetch CISA KEV feed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("CISA KEV HTTP %d", resp.StatusCode)
	}

	var feed cisaKEVFeed
	if err := json.NewDecoder(resp.Body).Decode(&feed); err != nil {
		return fmt.Errorf("decode CISA KEV JSON: %w", err)
	}

	newMap := make(map[string]KEVEntry, len(feed.Vulnerabilities))
	sorted := make([]KEVEntry, len(feed.Vulnerabilities))
	copy(sorted, feed.Vulnerabilities)

	for _, entry := range feed.Vulnerabilities {
		newMap[strings.ToUpper(strings.TrimSpace(entry.CVEID))] = entry
	}

	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].DateAdded > sorted[j].DateAdded
	})

	k.mu.Lock()
	k.byID = newMap
	k.list = sorted
	k.lastFetch = time.Now()
	k.mu.Unlock()
	return nil
}

func (k *KEVClient) Lookup(cveID string) *KEVEntry {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if entry, ok := k.byID[strings.ToUpper(strings.TrimSpace(cveID))]; ok {
		cp := entry
		return &cp
	}
	return nil
}

func (k *KEVClient) Latest(ctx context.Context, limit int, keyword string) ([]KEVEntry, error) {
	if err := k.EnsureLoaded(ctx); err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 5
	}
	if limit > 10 {
		limit = 10
	}

	kw := strings.ToLower(strings.TrimSpace(keyword))

	k.mu.RLock()
	defer k.mu.RUnlock()

	var out []KEVEntry
	for _, item := range k.list {
		if kw != "" {
			haystack := strings.ToLower(item.CVEID + " " + item.VendorProject + " " + item.Product + " " + item.VulnerabilityName + " " + item.ShortDescription)
			if !strings.Contains(haystack, kw) {
				continue
			}
		}
		out = append(out, item)
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}
