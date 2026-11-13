package approve

// ReviewDoc is the structured content of a review dialog: who asks, what will happen, and a table
// of the items to approve. The producer sanitizes every string; Text is the full plain-text form
// (the same text the phone shows), offered behind "Xem toàn văn".
type ReviewDoc struct {
	Requester string      `json:"requester"` // "kg.exe (pid 1234)"
	Chain     string      `json:"chain"`     // ancestors, "bash.exe ← omp.exe", or ""
	Action    string      `json:"action"`    // one line: what approving does
	Note      string      `json:"note"`      // one short explanatory sentence
	Badges    []Badge     `json:"badges"`
	Rows      []ReviewRow `json:"rows"`
	Text      string      `json:"text"`
}

// Badge tones.
const (
	ToneAdd   = "add"
	ToneMod   = "mod"
	ToneDel   = "del"
	ToneWarn  = "warn"
	ToneMuted = "muted"
)

// Badge is a short colored count shown above the table ("+1 thêm").
type Badge struct {
	Text string `json:"text"`
	Tone string `json:"tone"`
}

// Row groups.
const (
	GroupChange = "change"
	GroupWarn   = "warn"
	GroupKept   = "kept"
)

// ReviewRow is one line of the table; Detail (multi-line) is shown when the row is selected.
type ReviewRow struct {
	Group    string `json:"group"`
	Op       string `json:"op"` // add|mod|del|oracle|warn|kept: picks the icon
	Label    string `json:"label"`
	Secret   string `json:"secret"`
	Prod     bool   `json:"prod"`
	What     string `json:"what"`
	Approval string `json:"approval"`
	TTL      string `json:"ttl"`
	Detail   string `json:"detail"`
}
