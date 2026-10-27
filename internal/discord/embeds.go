package discord

import (
	"fmt"
	"math"
	"net/url"
	"strings"
	"time"

	"cve-discord-bot/internal/cve"

	"github.com/bwmarrin/discordgo"
)

const (
	ColorKEV      = 0xFF0055 // Vivid Cyber Crimson for Actively Exploited KEV
	ColorCritical = 0xE74C3C // Crimson Red
	ColorHigh     = 0xFF7A00 // Vibrant Tactical Orange
	ColorMedium   = 0xF1C40F // Amber Gold
	ColorLow      = 0x2ECC71 // Emerald / Low
	ColorUnknown  = 0x7F8C8D // Slate Gray
)

var cweNames = map[string]string{
	"CWE-20":  "Improper Input Validation",
	"CWE-22":  "Path Traversal",
	"CWE-74":  "Injection",
	"CWE-77":  "Command Injection",
	"CWE-78":  "OS Command Injection",
	"CWE-79":  "Cross-Site Scripting (XSS)",
	"CWE-89":  "SQL Injection (SQLi)",
	"CWE-94":  "Code Injection / RCE",
	"CWE-119": "Memory Buffer Overflow",
	"CWE-120": "Buffer Copy Overflow",
	"CWE-125": "Out-of-Bounds Read",
	"CWE-190": "Integer Overflow",
	"CWE-200": "Information Exposure",
	"CWE-201": "Sensitive Data Exposure",
	"CWE-269": "Improper Privilege Management",
	"CWE-276": "Incorrect Default Permissions",
	"CWE-284": "Improper Access Control",
	"CWE-287": "Improper Authentication",
	"CWE-306": "Missing Authentication",
	"CWE-352": "Cross-Site Request Forgery (CSRF)",
	"CWE-400": "Resource Exhaustion (DoS)",
	"CWE-416": "Use After Free (UAF)",
	"CWE-434": "Unrestricted File Upload",
	"CWE-476": "NULL Pointer Dereference",
	"CWE-502": "Insecure Deserialization",
	"CWE-601": "Open Redirect",
	"CWE-611": "XXE Injection",
	"CWE-639": "IDOR / BOLA",
	"CWE-787": "Out-of-Bounds Write",
	"CWE-798": "Hard-coded Credentials",
	"CWE-862": "Missing Authorization",
	"CWE-863": "Incorrect Authorization",
	"CWE-918": "Server-Side Request Forgery (SSRF)",
}

// BuildCVEEmbed creates a modern Threat Intel Rich Embed for a normalized CVEItem.
func BuildCVEEmbed(item cve.CVEItem) *discordgo.MessageEmbed {
	isKEV := item.KEV != nil
	color := severityColor(item.Severity, isKEV)
	badge := severityEmoji(item.Severity, isKEV)

	// Author Header Banner
	authorText := fmt.Sprintf("HUGINN THREAT INTEL  •  %s SEVERITY", emptyDefault(item.Severity, "UNSCORED"))
	if isKEV {
		authorText = "🚨 CISA KEV ALERT  •  ACTIVELY EXPLOITED IN THE WILD"
	}

	// Smart Headline Title
	headline := buildHeadline(item)
	title := fmt.Sprintf("%s %s — %s", badge, item.ID, truncate(headline, 180))

	// Clean Blockquote Summary
	desc := strings.TrimSpace(item.Description)
	if desc == "" && isKEV {
		desc = strings.TrimSpace(item.KEV.ShortDescription)
	}
	if desc == "" {
		desc = "No description provided by NVD."
	}
	desc = formatBlockquote(truncate(desc, 520))

	var fields []*discordgo.MessageEmbedField

	// Row 1: 3-Column Tactical Grid (CVSS Score | Affected Target | Weakness CWE)
	scoreField := "`Pending Analysis`"
	if item.BaseScore > 0 {
		ver := item.CVSSVersion
		if ver == "" {
			ver = "3.x"
		}
		scoreField = fmt.Sprintf("**%.1f** / 10.0 (`%s`)\n`%s` _v%s_",
			item.BaseScore, item.Severity, scoreBar(item.BaseScore), ver)
	} else if item.Severity != "" && item.Severity != "UNKNOWN" {
		scoreField = fmt.Sprintf("**%s**", item.Severity)
	}
	fields = append(fields, &discordgo.MessageEmbedField{
		Name:   "📊 CVSS Score",
		Value:  scoreField,
		Inline: true,
	})

	targetField := formatTargetField(item)
	fields = append(fields, &discordgo.MessageEmbedField{
		Name:   "🎯 Affected Target",
		Value:  targetField,
		Inline: true,
	})

	cweField := formatCWEField(item.CWEs)
	fields = append(fields, &discordgo.MessageEmbedField{
		Name:   "🧬 Weakness",
		Value:  cweField,
		Inline: true,
	})

	// Row 2: Human-readable Attack Surface Badges (from CVSS Vector)
	if item.VectorString != "" {
		badges := humanizeVector(item.VectorString)
		vecVal := fmt.Sprintf("`%s`", item.VectorString)
		if badges != "" {
			vecVal = badges + "\n`" + item.VectorString + "`"
		}
		fields = append(fields, &discordgo.MessageEmbedField{
			Name:   "🧭 Exploitability & Attack Surface",
			Value:  vecVal,
			Inline: false,
		})
	}

	// Row 3: CISA KEV Callout (if actively exploited)
	if isKEV {
		ransom := item.KEV.KnownRansomwareCampaignUse
		if ransom == "" {
			ransom = "Unknown"
		}
		kevVal := fmt.Sprintf(
			"• **Vendor / Product:** `%s` / `%s`\n"+
				"• **Added to KEV:** `%s`  |  **Patch Due:** `%s`\n"+
				"• **Ransomware Use:** `%s`\n"+
				"• **Mandated Action:** %s",
			item.KEV.VendorProject,
			item.KEV.Product,
			item.KEV.DateAdded,
			item.KEV.DueDate,
			ransom,
			truncate(item.KEV.RequiredAction, 200),
		)
		fields = append(fields, &discordgo.MessageEmbedField{
			Name:   "🔥 CISA Known Exploited Vulnerability (KEV)",
			Value:  kevVal,
			Inline: false,
		})
	}

	// Row 4: Domain-labeled References + Quick Threat Hunting Pivot Links
	refLines := formatReferences(item)
	fields = append(fields, &discordgo.MessageEmbedField{
		Name:   "🔗 Advisories & Threat Hunting",
		Value:  refLines,
		Inline: false,
	})

	pubStr := "Unknown"
	if !item.Published.IsZero() {
		pubStr = item.Published.Format("02 Jan 2006 15:04 UTC")
	}

	ts := time.Now().UTC().Format(time.RFC3339)
	if !item.Published.IsZero() {
		ts = item.Published.UTC().Format(time.RFC3339)
	}

	return &discordgo.MessageEmbed{
		Author: &discordgo.MessageEmbedAuthor{
			Name: authorText,
		},
		Title:       title,
		URL:         item.NVDURL(),
		Description: desc,
		Color:       color,
		Fields:      fields,
		Footer: &discordgo.MessageEmbedFooter{
			Text: fmt.Sprintf("🐦‍⬛ Huginn Threat Intel • NIST NVD v2.0 + CISA KEV • Published %s", pubStr),
		},
		Timestamp: ts,
	}
}

// BuildKEVEmbed converts a standalone KEVEntry into a rich embed.
func BuildKEVEmbed(entry cve.KEVEntry) *discordgo.MessageEmbed {
	item := cve.CVEItem{
		ID:          entry.CVEID,
		Description: entry.ShortDescription,
		Severity:    "CRITICAL",
		KEV:         &entry,
	}
	if t, err := time.Parse("2006-01-02", entry.DateAdded); err == nil {
		item.Published = t
	}
	return BuildCVEEmbed(item)
}

func buildHeadline(item cve.CVEItem) string {
	if item.KEV != nil && item.KEV.VulnerabilityName != "" {
		return item.KEV.VulnerabilityName
	}

	var vulnType string
	if len(item.CWEs) > 0 {
		if name, ok := cweNames[item.CWEs[0]]; ok {
			vulnType = name
		}
	}

	var target string
	if len(item.AffectedProducts) > 0 {
		target = item.AffectedProducts[0]
		if idx := strings.Index(target, " ("); idx > 0 {
			target = target[:idx]
		}
	} else {
		target = extractTargetFromDesc(item.Description)
	}

	if vulnType != "" && target != "" {
		return fmt.Sprintf("%s in %s", vulnType, target)
	}
	if target != "" {
		return target
	}
	if vulnType != "" {
		return vulnType
	}

	// Fallback: extract short first sentence of description
	d := strings.TrimSpace(item.Description)
	if d != "" {
		if idx := strings.Index(d, ". "); idx > 0 && idx < 95 {
			return d[:idx]
		}
		return truncate(d, 85)
	}
	return "Security Advisory"
}

func formatBlockquote(text string) string {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	for i, l := range lines {
		lines[i] = "> " + l
	}
	return strings.Join(lines, "\n")
}

func formatTargetField(item cve.CVEItem) string {
	if len(item.AffectedProducts) > 0 {
		var out []string
		for i, p := range item.AffectedProducts {
			if i >= 2 {
				break
			}
			out = append(out, "• `"+p+"`")
		}
		if len(item.AffectedProducts) > 2 {
			out = append(out, fmt.Sprintf("_+%d more targets_", len(item.AffectedProducts)-2))
		}
		return strings.Join(out, "\n")
	}
	if item.KEV != nil && item.KEV.Product != "" {
		return fmt.Sprintf("• `%s / %s`", item.KEV.VendorProject, item.KEV.Product)
	}
	if hint := extractTargetFromDesc(item.Description); hint != "" {
		return "• `" + hint + "`"
	}
	return "`Pending CPE Mapping`"
}

func extractTargetFromDesc(desc string) string {
	lower := strings.ToLower(desc)
	for _, marker := range []string{"vulnerability in ", "issue in ", "flaw in ", "discovered in "} {
		if idx := strings.Index(lower, marker); idx >= 0 {
			rest := strings.TrimSpace(desc[idx+len(marker):])
			for _, stop := range []string{" allows ", " may allow ", " could allow ", " before ", " through ", " prior to ", "."} {
				if sIdx := strings.Index(strings.ToLower(rest), stop); sIdx > 0 && sIdx < 55 {
					return strings.TrimSpace(rest[:sIdx])
				}
			}
			return truncate(rest, 40)
		}
	}
	return ""
}

func formatCWEField(cwes []string) string {
	if len(cwes) == 0 {
		return "`Unspecified`"
	}
	primary := cwes[0]
	if name, ok := cweNames[primary]; ok {
		return fmt.Sprintf("**`%s`**\n_%s_", primary, name)
	}
	return "`" + strings.Join(limitSlice(cwes, 2), "`, `") + "`"
}

func humanizeVector(vec string) string {
	parts := strings.Split(vec, "/")
	var badges []string
	for _, p := range parts {
		kv := strings.SplitN(p, ":", 2)
		if len(kv) != 2 {
			continue
		}
		k, v := kv[0], kv[1]
		switch k {
		case "AV":
			switch v {
			case "N":
				badges = append(badges, "🌐 `Network`")
			case "A":
				badges = append(badges, "📡 `Adjacent`")
			case "L":
				badges = append(badges, "💻 `Local`")
			case "P":
				badges = append(badges, "🔌 `Physical`")
			}
		case "AC":
			switch v {
			case "L":
				badges = append(badges, "⚡ `Low Complexity`")
			case "H":
				badges = append(badges, "🧩 `High Complexity`")
			}
		case "PR":
			switch v {
			case "N":
				badges = append(badges, "🔓 `No Auth Required`")
			case "L":
				badges = append(badges, "🔑 `Low Privs`")
			case "H":
				badges = append(badges, "👑 `Admin Privs`")
			}
		case "UI":
			switch v {
			case "N":
				badges = append(badges, "🎯 `Zero-Click`")
			case "R", "P", "A":
				badges = append(badges, "👆 `User Interaction`")
			}
		case "S":
			if v == "C" {
				badges = append(badges, "💥 `Scope Changed`")
			}
		}
	}
	return strings.Join(badges, " • ")
}

func formatReferences(item cve.CVEItem) string {
	var lines []string
	seenHost := make(map[string]int)

	for i, r := range item.References {
		if i >= 3 {
			break
		}
		label := domainLabel(r.URL)
		seenHost[label]++
		if seenHost[label] > 1 {
			label = fmt.Sprintf("%s #%d", label, seenHost[label])
		}
		tagBadge := ""
		if len(r.Tags) > 0 {
			tagBadge = " `[" + strings.Join(limitSlice(r.Tags, 2), ", ") + "]`"
		}
		lines = append(lines, fmt.Sprintf("• [%s](%s)%s", label, r.URL, tagBadge))
	}

	pivots := fmt.Sprintf(
		"🔎 **[NVD Detail](%s)**  •  **[CVE.org](https://www.cve.org/CVERecord?id=%s)**  •  **[GitHub PoC Search](https://github.com/search?q=%s&type=repositories)**",
		item.NVDURL(), item.ID, url.QueryEscape(item.ID),
	)
	if len(lines) > 0 {
		return strings.Join(lines, "\n") + "\n\n" + pivots
	}
	return pivots
}

func domainLabel(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return "Advisory Link"
	}
	host := strings.TrimPrefix(strings.ToLower(u.Host), "www.")
	pathParts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if host == "github.com" && len(pathParts) >= 2 {
		return fmt.Sprintf("github.com/%s/%s", pathParts[0], pathParts[1])
	}
	return host
}

func severityColor(sev string, isKEV bool) int {
	if isKEV {
		return ColorKEV
	}
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return ColorCritical
	case "HIGH":
		return ColorHigh
	case "MEDIUM":
		return ColorMedium
	case "LOW":
		return ColorLow
	default:
		return ColorUnknown
	}
}

func severityEmoji(sev string, isKEV bool) string {
	if isKEV {
		return "🚨"
	}
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return "🔴"
	case "HIGH":
		return "🟠"
	case "MEDIUM":
		return "🟡"
	case "LOW":
		return "🟢"
	default:
		return "⚪"
	}
}

func scoreBar(score float64) string {
	filled := int(math.Round(score))
	if filled < 0 {
		filled = 0
	}
	if filled > 10 {
		filled = 10
	}
	return strings.Repeat("█", filled) + strings.Repeat("░", 10-filled)
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

func limitSlice(in []string, max int) []string {
	if len(in) <= max {
		return in
	}
	return in[:max]
}
