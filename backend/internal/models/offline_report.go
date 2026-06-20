package models

import "time"

// OfflineReport mirrors the JSON structure emitted by the offline agent
// reporter. It is shared by the offline-report import flow and the AI analysis
// collector, so it lives in models rather than either handler.
type OfflineReport struct {
	BundleName  string `json:"bundle_name"`
	CaseID      string `json:"case_id"`
	CaseName    string `json:"case_name"`
	Hostname    string `json:"hostname"`
	IP          string `json:"ip"`
	OS          string `json:"os"`
	Arch        string `json:"arch"`
	GeneratedAt string `json:"generated_at"`
	Jobs        []struct {
		ToolName    string    `json:"tool_name"`
		ToolID      string    `json:"tool_id"`
		Args        string    `json:"args"`
		Status      string    `json:"status"`
		StartedAt   time.Time `json:"started_at"`
		FinishedAt  time.Time `json:"finished_at"`
		DurationSec float64   `json:"duration_seconds"`
		OutputLines int       `json:"output_lines"`
		Output      string    `json:"output"`
		Error       string    `json:"error"`
	} `json:"jobs"`
	Summary struct {
		TotalTools int `json:"total_tools"`
		Done       int `json:"done"`
		Failed     int `json:"failed"`
		Stopped    int `json:"stopped"`
	} `json:"summary"`
}
