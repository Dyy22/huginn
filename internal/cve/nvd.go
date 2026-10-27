package cve

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

const nvdBaseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

type NVDClient struct {
	httpClient  *http.Client
	apiKey      string
	kev         *KEVClient
	mu          sync.Mutex
	lastRequest time.Time
	minInterval time.Duration
}

func NewNVDClient(apiKey string, kev *KEVClient) *NVDClient {
	// NVD public rate limit: 5 requests per 30s (~6s spacing) without key,
	// 50 requests per 30s (~650ms spacing) with key.
	interval := 6200 * time.Millisecond
	if strings.TrimSpace(apiKey) != "" {
		interval = 700 * time.Millisecond
	}
	return &NVDClient{
		httpClient:  &http.Client{Timeout: 60 * time.Second},
		apiKey:      strings.TrimSpace(apiKey),
		kev:         kev,
		minInterval: interval,
	}
}

type SearchOptions struct {
	Keyword      string
	Severity     string // LOW, MEDIUM, HIGH, CRITICAL
	CVEID        string
	PubStartDate *time.Time
	PubEndDate   *time.Time
	Limit        int
}

// Raw NVD API v2.0 response structures
type nvdResponse struct {
	ResultsPerPage  int               `json:"resultsPerPage"`
	StartIndex      int               `json:"startIndex"`
	TotalResults    int               `json:"totalResults"`
	Vulnerabilities []nvdVulnWrapper  `json:"vulnerabilities"`
}

type nvdVulnWrapper struct {
	CVE nvdCVE `json:"cve"`
}

type nvdCVE struct {
	ID               string           `json:"id"`
	Published        string           `json:"published"`
	LastModified     string           `json:"lastModified"`
	Descriptions     []nvdLangString  `json:"descriptions"`
	Metrics          nvdMetrics       `json:"metrics"`
	Weaknesses       []nvdWeakness    `json:"weaknesses"`
	Configurations   []nvdConfig      `json:"configurations"`
	Affected         []nvdAffected    `json:"affected"`
	References       []nvdReference   `json:"references"`
}

type nvdAffected struct {
	AffectedData []nvdAffectedData `json:"affectedData"`
}

type nvdAffectedData struct {
	Vendor      string           `json:"vendor"`
	Product     string           `json:"product"`
	PackageName string           `json:"packageName"`
	Versions    []nvdAffectedVer `json:"versions"`
}

type nvdAffectedVer struct {
	Version         string `json:"version"`
	LessThan        string `json:"lessThan"`
	LessThanOrEqual string `json:"lessThanOrEqual"`
	Status          string `json:"status"`
}

type nvdLangString struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type nvdMetrics struct {
	CVSSMetricV40 []nvdCVSSMetricV3 `json:"cvssMetricV40"`
	CVSSMetricV31 []nvdCVSSMetricV3 `json:"cvssMetricV31"`
	CVSSMetricV30 []nvdCVSSMetricV3 `json:"cvssMetricV30"`
	CVSSMetricV2  []nvdCVSSMetricV2 `json:"cvssMetricV2"`
}

type nvdCVSSMetricV3 struct {
	Type     string      `json:"type"`
	CVSSData nvdCVSSData `json:"cvssData"`
}

type nvdCVSSMetricV2 struct {
	Type         string      `json:"type"`
	BaseSeverity string      `json:"baseSeverity"`
	CVSSData     nvdCVSSData `json:"cvssData"`
}

type nvdCVSSData struct {
	Version      string  `json:"version"`
	VectorString string  `json:"vectorString"`
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

type nvdWeakness struct {
	Description []nvdLangString `json:"description"`
}

type nvdConfig struct {
	Nodes []nvdNode `json:"nodes"`
}

type nvdNode struct {
	CPEMatch []nvdCPEMatch `json:"cpeMatch"`
}

type nvdCPEMatch struct {
	Vulnerable bool   `json:"vulnerable"`
	Criteria   string `json:"criteria"`
}

type nvdReference struct {
	URL    string   `json:"url"`
	Source string   `json:"source"`
	Tags   []string `json:"tags"`
}

func (c *NVDClient) waitRateLimit(ctx context.Context) error {
	c.mu.Lock()
	wait := c.minInterval - time.Since(c.lastRequest)
	if wait > 0 {
		c.lastRequest = time.Now().Add(wait)
	} else {
		c.lastRequest = time.Now()
	}
	c.mu.Unlock()

	if wait > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
	return nil
}

func (c *NVDClient) Search(ctx context.Context, opts SearchOptions) ([]CVEItem, int, error) {
	if c.kev != nil {
		_ = c.kev.EnsureLoaded(ctx)
	}

	params := url.Values{}
	if opts.CVEID != "" {
		params.Set("cveId", strings.ToUpper(strings.TrimSpace(opts.CVEID)))
	} else {
		if kw := strings.TrimSpace(opts.Keyword); kw != "" {
			params.Set("keywordSearch", kw)
		}
		if sev := strings.ToUpper(strings.TrimSpace(opts.Severity)); sev != "" && sev != "ALL" && sev != "ANY" {
			params.Set("cvssV3Severity", sev)
		}
		if opts.PubStartDate != nil && opts.PubEndDate != nil {
			const nvdTimeFmt = "2006-01-02T15:04:05.000"
			params.Set("pubStartDate", opts.PubStartDate.UTC().Format(nvdTimeFmt))
			params.Set("pubEndDate", opts.PubEndDate.UTC().Format(nvdTimeFmt))
		}
		fetchSize := 100
		if opts.Limit > fetchSize {
			fetchSize = opts.Limit
		}
		params.Set("resultsPerPage", fmt.Sprintf("%d", fetchSize))
	}

	raw, err := c.doNVDRequest(ctx, params)
	if err != nil {
		return nil, 0, err
	}

	// NVD orders results oldest-first (from 1999 -> present).
	// If there are more results than our page size, fetch the tail page so we always return the NEWEST CVEs.
	fetchSize := 100
	if opts.Limit > fetchSize {
		fetchSize = opts.Limit
	}
	if opts.CVEID == "" && raw.TotalResults > len(raw.Vulnerabilities) && raw.TotalResults > fetchSize {
		startIdx := raw.TotalResults - fetchSize
		params.Set("startIndex", fmt.Sprintf("%d", startIdx))
		if tailRaw, err := c.doNVDRequest(ctx, params); err == nil && len(tailRaw.Vulnerabilities) > 0 {
			raw = tailRaw
		}
	}

	items := make([]CVEItem, 0, len(raw.Vulnerabilities))
	for _, w := range raw.Vulnerabilities {
		item := c.normalizeCVE(w.CVE)
		if strings.HasPrefix(item.Description, "** REJECT **") || strings.HasPrefix(item.Description, "Rejected reason:") {
			continue
		}
		items = append(items, item)
	}

	// Sort newest published first so keyword search returns the latest CVEs instead of old 1999 CVEs.
	sort.Slice(items, func(i, j int) bool {
		return items[i].Published.After(items[j].Published)
	})

	limit := opts.Limit
	if limit <= 0 {
		limit = 5
	}
	if len(items) > limit {
		items = items[:limit]
	}

	return items, raw.TotalResults, nil
}

func (c *NVDClient) doNVDRequest(ctx context.Context, params url.Values) (*nvdResponse, error) {
	if err := c.waitRateLimit(ctx); err != nil {
		return nil, err
	}

	reqStart := time.Now()
	reqURL := nvdBaseURL + "?" + params.Encode()
	log.Printf("[NVD] GET %s", reqURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Huginn-ThreatIntel-Bot/1.0")
	if c.apiKey != "" {
		req.Header.Set("apiKey", c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("NVD API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		msg := strings.TrimSpace(resp.Header.Get("message"))
		if msg == "" {
			msg = strings.TrimSpace(string(body))
		}
		return nil, fmt.Errorf("NVD API HTTP %d (%s)", resp.StatusCode, msg)
	}

	var raw nvdResponse
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode NVD response: %w", err)
	}
	log.Printf("[NVD] Received %d vulnerabilities (totalResults=%d, startIndex=%d) in %s",
		len(raw.Vulnerabilities), raw.TotalResults, raw.StartIndex, time.Since(reqStart).Round(time.Millisecond))
	return &raw, nil
}

func (c *NVDClient) normalizeCVE(raw nvdCVE) CVEItem {
	item := CVEItem{
		ID:       raw.ID,
		Severity: "UNKNOWN",
	}

	if t, err := parseNVDTime(raw.Published); err == nil {
		item.Published = t
	}
	if t, err := parseNVDTime(raw.LastModified); err == nil {
		item.LastModified = t
	}

	for _, d := range raw.Descriptions {
		if d.Lang == "en" {
			item.Description = strings.TrimSpace(d.Value)
			break
		}
	}
	if item.Description == "" && len(raw.Descriptions) > 0 {
		item.Description = strings.TrimSpace(raw.Descriptions[0].Value)
	}

	// Extract CVSS metrics (prefer v3.1 -> v4.0 -> v3.0 -> v2.0)
	if len(raw.Metrics.CVSSMetricV31) > 0 {
		m := pickPrimaryV3(raw.Metrics.CVSSMetricV31)
		item.CVSSVersion = "3.1"
		item.BaseScore = m.CVSSData.BaseScore
		item.Severity = strings.ToUpper(m.CVSSData.BaseSeverity)
		item.VectorString = m.CVSSData.VectorString
	} else if len(raw.Metrics.CVSSMetricV40) > 0 {
		m := pickPrimaryV3(raw.Metrics.CVSSMetricV40)
		item.CVSSVersion = "4.0"
		item.BaseScore = m.CVSSData.BaseScore
		item.Severity = strings.ToUpper(m.CVSSData.BaseSeverity)
		item.VectorString = m.CVSSData.VectorString
	} else if len(raw.Metrics.CVSSMetricV30) > 0 {
		m := pickPrimaryV3(raw.Metrics.CVSSMetricV30)
		item.CVSSVersion = "3.0"
		item.BaseScore = m.CVSSData.BaseScore
		item.Severity = strings.ToUpper(m.CVSSData.BaseSeverity)
		item.VectorString = m.CVSSData.VectorString
	} else if len(raw.Metrics.CVSSMetricV2) > 0 {
		m := raw.Metrics.CVSSMetricV2[0]
		item.CVSSVersion = "2.0"
		item.BaseScore = m.CVSSData.BaseScore
		item.Severity = strings.ToUpper(m.BaseSeverity)
		item.VectorString = m.CVSSData.VectorString
	}

	// Extract unique CWEs
	cweSeen := make(map[string]bool)
	for _, w := range raw.Weaknesses {
		for _, desc := range w.Description {
			val := strings.TrimSpace(desc.Value)
			if val != "" && val != "NVD-CWE-noinfo" && val != "NVD-CWE-Other" && !cweSeen[val] {
				cweSeen[val] = true
				item.CWEs = append(item.CWEs, val)
			}
		}
	}

	// Extract readable vendor/product (+ version range) from NVD v2 affected[] and CPE configurations[]
	prodSeen := make(map[string]bool)
	for _, aff := range raw.Affected {
		for _, ad := range aff.AffectedData {
			vendor := strings.TrimSpace(ad.Vendor)
			product := strings.TrimSpace(ad.Product)
			if product == "" {
				product = strings.TrimSpace(ad.PackageName)
			}
			if product == "" {
				continue
			}
			label := product
			if vendor != "" && !strings.EqualFold(vendor, product) {
				label = vendor + " / " + product
			}
			for _, v := range ad.Versions {
				if strings.EqualFold(v.Status, "affected") || v.Status == "" {
					if v.LessThanOrEqual != "" {
						label += " (<= " + v.LessThanOrEqual + ")"
						break
					} else if v.LessThan != "" {
						label += " (< " + v.LessThan + ")"
						break
					} else if v.Version != "" && v.Version != "0" && v.Version != "n/a" && v.Version != "*" {
						label += " (" + v.Version + ")"
						break
					}
				}
			}
			if !prodSeen[strings.ToLower(label)] {
				prodSeen[strings.ToLower(label)] = true
				item.AffectedProducts = append(item.AffectedProducts, label)
			}
		}
	}

	for _, cfg := range raw.Configurations {
		for _, node := range cfg.Nodes {
			for _, match := range node.CPEMatch {
				parts := strings.Split(match.Criteria, ":")
				if len(parts) >= 5 {
					vendor := strings.ReplaceAll(parts[3], "_", " ")
					product := strings.ReplaceAll(parts[4], "_", " ")
					label := vendor + " / " + product
					if vendor != "*" && product != "*" && !prodSeen[strings.ToLower(label)] {
						prodSeen[strings.ToLower(label)] = true
						item.AffectedProducts = append(item.AffectedProducts, label)
					}
				}
			}
		}
	}

	for _, ref := range raw.References {
		item.References = append(item.References, Reference{
			URL:    ref.URL,
			Source: ref.Source,
			Tags:   ref.Tags,
		})
	}

	if c.kev != nil {
		item.KEV = c.kev.Lookup(item.ID)
	}

	return item
}

func pickPrimaryV3(list []nvdCVSSMetricV3) nvdCVSSMetricV3 {
	for _, m := range list {
		if strings.EqualFold(m.Type, "Primary") {
			return m
		}
	}
	return list[0]
}

func parseNVDTime(s string) (time.Time, error) {
	layouts := []string{
		"2006-01-02T15:04:05.999",
		"2006-01-02T15:04:05",
		time.RFC3339,
	}
	for _, l := range layouts {
		if t, err := time.Parse(l, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("cannot parse time %q", s)
}
