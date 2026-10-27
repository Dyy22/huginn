package news

import (
	"context"
	"encoding/xml"
	"html"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

type Article struct {
	Title         string
	URL           string
	Summary       string
	Source        string
	Category      string // breaking, research, writeups
	Published     time.Time
	ImageURL      string
	MentionedCVEs []string
}

type FeedSource struct {
	Name     string
	Category string
	URL      string
}

var DefaultFeeds = []FeedSource{
	{Name: "The Hacker News", Category: "breaking", URL: "https://feeds.feedburner.com/TheHackersNews"},
	{Name: "BleepingComputer", Category: "breaking", URL: "https://www.bleepingcomputer.com/feed/"},
	{Name: "Dark Reading", Category: "breaking", URL: "https://www.darkreading.com/rss.xml"},
	{Name: "PortSwigger Research", Category: "research", URL: "https://portswigger.net/research/rss"},
	{Name: "Google Project Zero", Category: "research", URL: "https://googleprojectzero.blogspot.com/feeds/posts/default?alt=rss"},
	{Name: "watchTowr Labs", Category: "research", URL: "https://labs.watchtowr.com/rss/"},
	{Name: "Intigriti Bug Bytes", Category: "writeups", URL: "https://blog.intigriti.com/feed/"},
	{Name: "Zero Day Initiative", Category: "research", URL: "https://www.zerodayinitiative.com/blog?format=rss"},
}

var (
	reCVE      = regexp.MustCompile(`(?i)\bCVE-\d{4}-\d{4,7}\b`)
	reHTMLTags = regexp.MustCompile(`<[^>]*>`)
	reImgSrc   = regexp.MustCompile(`(?i)<img[^>]+src=["']([^"']+)["']`)
	reSpaces   = regexp.MustCompile(`\s+`)
)

type Client struct {
	httpClient *http.Client
	feeds      []FeedSource
}

func NewClient() *Client {
	return &Client{
		httpClient: &http.Client{Timeout: 15 * time.Second},
		feeds:      DefaultFeeds,
	}
}

func (c *Client) Fetch(ctx context.Context, categories []string, keyword string, limit int) ([]Article, error) {
	catFilter := make(map[string]bool)
	for _, cat := range categories {
		cat = strings.ToLower(strings.TrimSpace(cat))
		if cat != "" && cat != "all" {
			catFilter[cat] = true
		}
	}

	var selected []FeedSource
	for _, f := range c.feeds {
		if len(catFilter) == 0 || catFilter[f.Category] {
			selected = append(selected, f)
		}
	}

	var (
		mu       sync.Mutex
		wg       sync.WaitGroup
		articles []Article
	)

	for _, src := range selected {
		wg.Add(1)
		go func(fs FeedSource) {
			defer wg.Done()
			items, err := c.fetchSingleFeed(ctx, fs)
			if err != nil {
				return
			}
			mu.Lock()
			articles = append(articles, items...)
			mu.Unlock()
		}(src)
	}
	wg.Wait()

	kw := strings.ToLower(strings.TrimSpace(keyword))
	var filtered []Article
	seenURL := make(map[string]bool)

	for _, a := range articles {
		if a.URL == "" || seenURL[a.URL] {
			continue
		}
		if kw != "" {
			haystack := strings.ToLower(a.Title + " " + a.Summary + " " + a.Source + " " + strings.Join(a.MentionedCVEs, " "))
			if !strings.Contains(haystack, kw) {
				continue
			}
		}
		seenURL[a.URL] = true
		filtered = append(filtered, a)
	}

	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].Published.After(filtered[j].Published)
	})

	if limit <= 0 {
		limit = 5
	}
	if len(filtered) > limit {
		filtered = filtered[:limit]
	}

	return filtered, nil
}

// RSS 2.0 / Atom hybrid XML structures
type rssRoot struct {
	Channel rssChannel  `xml:"channel"`
	Entries []atomEntry `xml:"entry"`
}

type rssChannel struct {
	Items []rssItem `xml:"item"`
}

type rssItem struct {
	Title       string        `xml:"title"`
	Link        string        `xml:"link"`
	Description string        `xml:"description"`
	Content     string        `xml:"encoded"`
	PubDate     string        `xml:"pubDate"`
	DCDate      string        `xml:"date"`
	Enclosure   rssEnclosure  `xml:"enclosure"`
	MediaThumb  rssMediaThumb `xml:"thumbnail"`
	MediaCont   rssMediaThumb `xml:"content"`
}

type rssEnclosure struct {
	URL  string `xml:"url,attr"`
	Type string `xml:"type,attr"`
}

type rssMediaThumb struct {
	URL string `xml:"url,attr"`
}

type atomEntry struct {
	Title     string     `xml:"title"`
	Links     []atomLink `xml:"link"`
	Summary   string     `xml:"summary"`
	Content   string     `xml:"content"`
	Published string     `xml:"published"`
	Updated   string     `xml:"updated"`
}

type atomLink struct {
	Href string `xml:"href,attr"`
	Rel  string `xml:"rel,attr"`
}

func (c *Client) fetchSingleFeed(ctx context.Context, src FeedSource) ([]Article, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Huginn-ThreatIntel-Bot/1.0 (+https://github.com/Dyy22/huginn)")
	req.Header.Set("Accept", "application/rss+xml, application/xml, text/xml, */*")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return nil, err
	}

	var root rssRoot
	if err := xml.Unmarshal(body, &root); err != nil {
		return nil, err
	}

	var out []Article
	for _, it := range root.Channel.Items {
		rawDesc := it.Description
		if rawDesc == "" {
			rawDesc = it.Content
		}
		imgURL := it.Enclosure.URL
		if imgURL == "" {
			imgURL = it.MediaThumb.URL
		}
		if imgURL == "" {
			imgURL = it.MediaCont.URL
		}
		if imgURL == "" {
			if m := reImgSrc.FindStringSubmatch(rawDesc); len(m) > 1 {
				imgURL = m[1]
			} else if m := reImgSrc.FindStringSubmatch(it.Content); len(m) > 1 {
				imgURL = m[1]
			}
		}

		cleanTitle := cleanText(it.Title)
		cleanDesc := cleanText(rawDesc)
		pubTime := parseFeedTime(it.PubDate, it.DCDate)

		out = append(out, Article{
			Title:         cleanTitle,
			URL:           strings.TrimSpace(it.Link),
			Summary:       cleanDesc,
			Source:        src.Name,
			Category:      src.Category,
			Published:     pubTime,
			ImageURL:      strings.TrimSpace(imgURL),
			MentionedCVEs: extractCVEs(cleanTitle + " " + cleanDesc),
		})
	}

	for _, en := range root.Entries {
		link := ""
		for _, l := range en.Links {
			if l.Rel == "alternate" || l.Rel == "" {
				link = l.Href
				break
			}
		}
		if link == "" && len(en.Links) > 0 {
			link = en.Links[0].Href
		}
		rawDesc := en.Summary
		if rawDesc == "" {
			rawDesc = en.Content
		}
		cleanTitle := cleanText(en.Title)
		cleanDesc := cleanText(rawDesc)
		pubTime := parseFeedTime(en.Published, en.Updated)

		out = append(out, Article{
			Title:         cleanTitle,
			URL:           strings.TrimSpace(link),
			Summary:       cleanDesc,
			Source:        src.Name,
			Category:      src.Category,
			Published:     pubTime,
			MentionedCVEs: extractCVEs(cleanTitle + " " + cleanDesc),
		})
	}

	return out, nil
}

func cleanText(s string) string {
	s = html.UnescapeString(s)
	s = reHTMLTags.ReplaceAllString(s, " ")
	s = html.UnescapeString(s)
	s = reSpaces.ReplaceAllString(s, " ")
	return strings.TrimSpace(s)
}

func extractCVEs(text string) []string {
	matches := reCVE.FindAllString(text, -1)
	seen := make(map[string]bool)
	var out []string
	for _, m := range matches {
		up := strings.ToUpper(m)
		if !seen[up] {
			seen[up] = true
			out = append(out, up)
		}
	}
	return out
}

func parseFeedTime(candidates ...string) time.Time {
	layouts := []string{
		time.RFC1123Z,
		time.RFC1123,
		time.RFC3339,
		"Mon, 2 Jan 2006 15:04:05 -0700",
		"Mon, 2 Jan 2006 15:04:05 MST",
		"2006-01-02T15:04:05-07:00",
		"2006-01-02 15:04:05",
	}
	for _, raw := range candidates {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		for _, layout := range layouts {
			if t, err := time.Parse(layout, raw); err == nil {
				return t.UTC()
			}
		}
	}
	return time.Now().UTC()
}
