# AI Analysis — how the pieces fit

AnalysisHub has **two complementary AI outputs**. Knowing which one you want
avoids confusion when you see several "AI" buttons.

| Output | What it produces | Where it lands | Entry points |
|--------|------------------|----------------|--------------|
| **Structured findings** | A list of concrete security findings (severity, MITRE technique, confidence, indicator) | The **case attack timeline** (Source=`ai`) + the **IOC store** | Job → *Extract findings → timeline*; Case → *Analyze Evidence*; EdgeForensics → *AI triage → timeline* |
| **Narrative report** | A free-form DFIR write-up, streamed live with a visible chain of work | An **AI Analysis session** (viewable, re-openable) | AI Analysis page (source: job / checklist / ELK / upload / offline / **evidence**); Job → *Open AI narrative report*; Evidence Store → the 🧠 button |

## The investigation flow

```
Case → assign agents → run tools / scenarios → results collected
   → findings extracted (auto or manual) ──► Case timeline + IOC store
   → "AI Summary" narrates the enriched timeline ──► Incident report / STIX
```

- **Structured findings** are the primary path: they are deduped, carry a
  clickable source, and correlate across every host in a case.
- **Narrative reports** are for reading/triage of one artifact in depth — open
  from the Evidence Store 🧠 button or the AI Analysis page.

## Engine notes

- Large inputs are handled by **map-reduce**: each chunk is summarized (MAP) in
  parallel, then the summaries are reduced to findings in budget-sized batches, so
  a big file is covered rather than truncated. See `internal/api/handlers/tool_result_ai.go` (`analyzeTextContent`, `reduceFindings`, `promoteFindings`).
- Reasoning models (e.g. `deepseek-reasoner`, `o1`/`o3`) automatically skip
  `temperature` / `response_format` to avoid 400s. See `internal/ai/openai.go` (`isReasoningModel`).
- **Auto-analyze** (opt-in per tool) runs findings extraction automatically once a
  job with collected results finishes — hands-off collect → analyze.
- A "0 findings" result is legitimate for benign data. If it looks wrong, check
  the backend log for `[ai-findings] unparseable model output` — that means the
  model returned non-JSON (prompt/model mismatch), not that nothing was found.

## Evidence Store

Files enter the central store from four sources — manual upload, auto-collected
tool results, checklist runs, and edge-forensics scans — each tagged with `kind`
and `host`. The 🧠 button opens a detailed **narrative** AI Analysis of that file.
Retention (`RETENTION_*` env) can auto-prune closed/unlinked evidence; it never
touches evidence attached to an open case, and is dry-run by default.
