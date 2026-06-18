package offline

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorCyan   = "\033[36m"
	colorGray   = "\033[90m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"
)

// RunCLI runs the interactive terminal UI for headless/SSH environments.
// It blocks until the user types "quit" or "exit".
func RunCLI(manifest *BundleManifest, runner *Runner) {
	printBanner(manifest)
	printTools(manifest)

	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Printf("\n%s%s>%s ", colorBold, colorCyan, colorReset)
		if !scanner.Scan() {
			break
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		cmd := strings.ToLower(parts[0])

		switch cmd {
		case "quit", "exit", "q":
			fmt.Println(colorGray + "Goodbye." + colorReset)
			return

		case "run", "r":
			handleRun(manifest, runner, parts[1:])

		case "stop", "s":
			if len(parts) < 2 {
				printError("Usage: stop <job-id>")
				continue
			}
			runner.StopJob(parts[1])
			fmt.Printf("%s[*] Stop signal sent to %s%s\n", colorYellow, parts[1], colorReset)

		case "status", "jobs", "ls":
			printJobStatus(runner)

		case "tools", "t":
			printTools(manifest)

		case "output", "out":
			if len(parts) < 2 {
				printError("Usage: output <job-id>")
				continue
			}
			printJobOutput(runner, parts[1])

		case "report":
			generateCLIReport(manifest, runner)

		case "help", "h", "?":
			printHelp()

		default:
			printError("Unknown command: " + cmd + "  (type 'help' for commands)")
		}
	}
}

// ── Command handlers ──────────────────────────────────────────────────────────

func handleRun(manifest *BundleManifest, runner *Runner, args []string) {
	if len(args) == 0 {
		printError("Usage: run <tool-number|tool-name> [custom args...]")
		return
	}

	tool := findTool(manifest, args[0])
	if tool == nil {
		printError(fmt.Sprintf("Tool not found: %q", args[0]))
		return
	}

	customArgs := ""
	if len(args) > 1 {
		customArgs = strings.Join(args[1:], " ")
	}

	fmt.Printf("%s[*] Starting: %s%s%s\n", colorBlue, colorBold, tool.Name, colorReset)
	if customArgs != "" {
		fmt.Printf("%s    args: %s%s\n", colorGray, customArgs, colorReset)
	} else if tool.DefaultArgs != "" {
		fmt.Printf("%s    args: %s (default)%s\n", colorGray, tool.DefaultArgs, colorReset)
	}

	job, err := runner.StartJob(*tool, customArgs)
	if err != nil {
		printError("Failed to start job: " + err.Error())
		return
	}

	fmt.Printf("%s[+] Job started: %s%s\n", colorGreen, job.ID, colorReset)
	fmt.Printf("%s    Press Enter to continue; output streams in background.%s\n", colorDim, colorReset)
	fmt.Printf("%s    Use 'output %s' to view accumulated output.%s\n", colorDim, job.ID, colorReset)

	// Stream output to terminal in a goroutine, prefixed so it doesn't
	// interrupt interactive input too badly.
	history, ch := runner.Subscribe(job.ID)
	go func() {
		for _, line := range history {
			printOutputLine(job.ID, line)
		}
		for line := range ch {
			printOutputLine(job.ID, line)
		}
		// Job finished.
		j := runner.GetJob(job.ID)
		if j != nil {
			printJobFinished(j)
		}
	}()
}

func printJobStatus(runner *Runner) {
	jobs := runner.ListJobs()
	if len(jobs) == 0 {
		fmt.Println(colorGray + "  No jobs run yet." + colorReset)
		return
	}
	fmt.Printf("\n%s%-12s %-20s %-10s %-8s %s%s\n",
		colorBold, "JOB ID", "TOOL", "STATUS", "LINES", "DURATION", colorReset)
	fmt.Println(colorGray + strings.Repeat("─", 65) + colorReset)
	for _, j := range jobs {
		col := statusColor(j.Status)
		dur := ""
		if j.StartedAt != nil && j.FinishedAt != nil {
			d := j.FinishedAt.Sub(*j.StartedAt)
			dur = fmtDuration(d)
		}
		fmt.Printf("%-12s %-20s %s%-10s%s %-8d %s\n",
			j.ID,
			truncate(j.ToolName, 20),
			col, string(j.Status), colorReset,
			len(j.Output),
			dur,
		)
	}
}

func printJobOutput(runner *Runner, jobID string) {
	job := runner.GetJob(jobID)
	if job == nil {
		printError("Job not found: " + jobID)
		return
	}
	fmt.Printf("\n%s%s=== Output: %s ===%s\n", colorBold, colorCyan, job.ToolName, colorReset)
	for _, line := range job.Output {
		fmt.Println(line)
	}
	fmt.Printf("%s=== End (%d lines) ===%s\n", colorGray, len(job.Output), colorReset)
}

func generateCLIReport(manifest *BundleManifest, runner *Runner) {
	hostname, _ := os.Hostname()
	ts := time.Now().Format("20060102-150405")
	base := fmt.Sprintf("report-%s-%s", safeFilename(hostname), ts)

	rep := BuildReport(manifest, runner)

	htmlPath := base + ".html"
	jsonPath := base + ".json"

	if err := SaveHTML(rep, htmlPath); err != nil {
		printError("HTML report failed: " + err.Error())
	} else {
		fmt.Printf("%s[+] HTML report: %s%s\n", colorGreen, htmlPath, colorReset)
	}

	if err := SaveJSON(rep, jsonPath); err != nil {
		printError("JSON report failed: " + err.Error())
	} else {
		fmt.Printf("%s[+] JSON report: %s%s\n", colorGreen, jsonPath, colorReset)
	}
}

// ── Print helpers ─────────────────────────────────────────────────────────────

func printBanner(manifest *BundleManifest) {
	hostname, _ := os.Hostname()
	ip := localIP()
	fmt.Printf(`
%s%s╔══════════════════════════════════════════════════════════════╗%s
%s║  ForensicHub Offline Agent                                   ║%s
%s║  Bundle : %-51s║%s`,
		colorBold, colorCyan, colorReset,
		colorCyan, colorReset,
		colorCyan, padRight(manifest.Name, 51), colorReset,
	)
	if manifest.CaseName != "" {
		fmt.Printf(`
%s║  Case   : %-51s║%s`, colorCyan, padRight(manifest.CaseName, 51), colorReset)
	}
	fmt.Printf(`
%s║  Host   : %-51s║%s
%s║  IP     : %-51s║%s
%s╚══════════════════════════════════════════════════════════════╝%s
`,
		colorCyan, padRight(hostname, 51), colorReset,
		colorCyan, padRight(ip, 51), colorReset,
		colorCyan, colorReset,
	)
}

func printTools(manifest *BundleManifest) {
	fmt.Printf("\n%sBundled Tools:%s\n", colorBold, colorReset)
	for i, t := range manifest.Tools {
		desc := t.Description
		if desc == "" {
			desc = t.Category
		}
		fmt.Printf("  %s[%d]%s %-25s %s%s%s\n",
			colorYellow, i+1, colorReset,
			colorBold+t.Name+colorReset,
			colorGray, truncate(desc, 40), colorReset,
		)
		if t.DefaultArgs != "" {
			fmt.Printf("      %sdefault args: %s%s\n", colorDim, t.DefaultArgs, colorReset)
		}
	}
}

func printHelp() {
	fmt.Printf(`
%sCommands:%s
  %srun <n|name> [args]%s   Run tool by number or name (empty args = use defaults)
  %sstop <job-id>%s         Stop a running job
  %sstatus%s                List all jobs and their status
  %soutput <job-id>%s       Show full output of a job
  %stools%s                 List bundled tools
  %sreport%s                Generate HTML + JSON report files
  %squit%s                  Exit
`,
		colorBold, colorReset,
		colorCyan, colorReset,
		colorCyan, colorReset,
		colorCyan, colorReset,
		colorCyan, colorReset,
		colorCyan, colorReset,
		colorCyan, colorReset,
		colorCyan, colorReset,
	)
}

func printOutputLine(jobID, line string) {
	lower := strings.ToLower(line)
	col := colorGray
	if strings.Contains(lower, "error") || strings.Contains(lower, "[!]") {
		col = colorRed
	} else if strings.Contains(lower, "found") || strings.Contains(lower, "[+]") {
		col = colorGreen
	} else if strings.Contains(lower, "warn") || strings.Contains(lower, "[?]") {
		col = colorYellow
	}
	fmt.Printf("%s[%s] %s%s\n", col, jobID, line, colorReset)
}

func printJobFinished(j *Job) {
	col := colorGreen
	if j.Status == StatusFailed {
		col = colorRed
	} else if j.Status == StatusStopped {
		col = colorYellow
	}
	fmt.Printf("\n%s%s[✓] Job %s finished: %s%s\n", colorBold, col, j.ID, string(j.Status), colorReset)
	fmt.Printf("%s    Use 'output %s' to view full output, or 'report' to save results.%s\n\n",
		colorDim, j.ID, colorReset)
}

func printError(msg string) {
	fmt.Printf("%s[!] %s%s\n", colorRed, msg, colorReset)
}

// ── Util ─────────────────────────────────────────────────────────────────────

func findTool(manifest *BundleManifest, ref string) *BundleTool {
	// Try numeric index first.
	idx := 0
	for _, c := range ref {
		if c >= '0' && c <= '9' {
			idx = idx*10 + int(c-'0')
		} else {
			idx = -1
			break
		}
	}
	if idx > 0 && idx <= len(manifest.Tools) {
		return &manifest.Tools[idx-1]
	}
	// Name match (case-insensitive prefix).
	lower := strings.ToLower(ref)
	for i, t := range manifest.Tools {
		if strings.HasPrefix(strings.ToLower(t.Name), lower) || strings.EqualFold(t.ID, ref) {
			return &manifest.Tools[i]
		}
	}
	return nil
}

func statusColor(s JobStatus) string {
	switch s {
	case StatusDone:
		return colorGreen
	case StatusFailed:
		return colorRed
	case StatusStopped:
		return colorYellow
	case StatusRunning:
		return colorBlue
	default:
		return colorGray
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func padRight(s string, n int) string {
	if len(s) >= n {
		return s[:n]
	}
	return s + strings.Repeat(" ", n-len(s))
}

func fmtDuration(d time.Duration) string {
	s := d.Seconds()
	if s < 60 {
		return fmt.Sprintf("%.1fs", s)
	}
	return fmt.Sprintf("%dm%ds", int(s)/60, int(s)%60)
}
