package cve

import "time"

// CVEItem is the normalized internal representation of a CVE enriched with NVD + CISA KEV data.
type CVEItem struct {
	ID               string
	Description      string
	Published        time.Time
	LastModified     time.Time
	CVSSVersion      string
	BaseScore        float64
	Severity         string // CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN
	VectorString     string
	CWEs             []string
	AffectedProducts []string
	References       []Reference
	KEV              *KEVEntry
}

type Reference struct {
	URL    string
	Source string
	Tags   []string
}

type KEVEntry struct {
	CVEID                      string `json:"cveID"`
	VendorProject              string `json:"vendorProject"`
	Product                    string `json:"product"`
	VulnerabilityName          string `json:"vulnerabilityName"`
	DateAdded                  string `json:"dateAdded"`
	ShortDescription           string `json:"shortDescription"`
	RequiredAction             string `json:"requiredAction"`
	DueDate                    string `json:"dueDate"`
	KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
	Notes                      string `json:"notes"`
}

func (c *CVEItem) NVDURL() string {
	return "https://nvd.nist.gov/vuln/detail/" + c.ID
}
