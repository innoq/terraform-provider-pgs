package sqlrun

// Request is the JSON document the remote helper (cmd/pgs-sqlhelper) reads from stdin.
type Request struct {
	Path          string        `json:"path"`
	BusyTimeoutMS int           `json:"busy_timeout_ms"`
	Write         bool          `json:"write"`
	Statements    []RequestStmt `json:"statements"`
}

// RequestStmt is one Statement on the wire.
type RequestStmt struct {
	SQL   string `json:"sql"`
	Args  []any  `json:"args"`
	Query bool   `json:"query"`
}

// Response is the JSON document the helper writes to stdout.
type Response struct {
	Results []string `json:"results"`
	Error   string   `json:"error,omitempty"`
}
