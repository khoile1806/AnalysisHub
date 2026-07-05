package logsearch

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

// categoryView is a Kibana data view. Names/patterns mirror the index naming
// hunt-<category>-<case>-<logtype> so an analyst can browse logs grouped by
// platform (Windows, Linux, Firewall…) or all at once.
type categoryView struct{ name, pattern string }

// categoryViewByKey maps a log category to its data view.
var categoryViewByKey = map[string]categoryView{
	"windows":  {"Windows Event Logs", IndexPrefix + "-windows-*"},
	"linux":    {"Linux Syslog", IndexPrefix + "-linux-*"},
	"firewall": {"Firewall", IndexPrefix + "-firewall-*"},
	"web":      {"Web Access", IndexPrefix + "-web-*"},
	"app":      {"JSON / Application", IndexPrefix + "-app-*"},
	"other":    {"Other Logs", IndexPrefix + "-other-*"},
}

func categoryViews() []categoryView {
	views := []categoryView{{"Hunt Logs", IndexPrefix + "-*"}} // all
	for _, k := range []string{"windows", "linux", "firewall", "web", "app", "other"} {
		views = append(views, categoryViewByKey[k])
	}
	return views
}

// EnsureCategoryDataView creates the data view for a single category (and the
// catch-all) right after an ingest, so the right view exists even if the startup
// provisioning missed it. Best-effort; quick and quiet.
func EnsureCategoryDataView(kibanaURL, category string) {
	kibanaURL = strings.TrimRight(strings.TrimSpace(kibanaURL), "/")
	if kibanaURL == "" {
		return
	}
	client := &http.Client{Timeout: 15 * time.Second}
	createDataView(client, kibanaURL, "Hunt Logs", IndexPrefix+"-*")
	if cv, ok := categoryViewByKey[category]; ok {
		createDataView(client, kibanaURL, cv.name, cv.pattern)
	}
}

// EnsureKibanaDataView waits for Kibana to come up then best-effort creates one
// data view per category so ingested logs are immediately browsable in Discover
// and usable as the source for detection rules. kibanaURL must include the base
// path (e.g. http://kibana:5601/kbn). Safe to call in a goroutine; it never
// blocks startup and gives up quietly if Kibana stays unreachable.
func EnsureKibanaDataView(kibanaURL string) {
	kibanaURL = strings.TrimRight(strings.TrimSpace(kibanaURL), "/")
	if kibanaURL == "" {
		return
	}
	client := &http.Client{Timeout: 15 * time.Second}

	// wait for Kibana /api/status (up to ~5 minutes)
	ready := false
	for i := 0; i < 60; i++ {
		resp, err := client.Get(kibanaURL + "/api/status")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				ready = true
				break
			}
		}
		time.Sleep(5 * time.Second)
	}
	if !ready {
		log.Printf("logsearch: kibana not reachable, skipped data view creation")
		return
	}

	for _, cv := range categoryViews() {
		createDataView(client, kibanaURL, cv.name, cv.pattern)
	}
	provisionThreatSearches(client, kibanaURL)
	provisionAlertRules(client, kibanaURL)
}

// alertRule is a Stack Alerting (.es-query) rule that fires when the count of
// matching docs over hunt-* in the time window exceeds a threshold. These work
// on a basic license without security (the encryption key must be set in Kibana).
type alertRule struct {
	id, name, query string
	threshold       int
}

func alertRules() []alertRule {
	return []alertRule{
		{"hunt-alert-ssh-bruteforce", "SSH brute-force",
			"event.action:ssh_login AND event.outcome:failure", 5},
		{"hunt-alert-win-logon-spike", "Windows failed-logon spike (4625)",
			"event.code:4625", 10},
		{"hunt-alert-fw-c2", "Firewall block to C2-ish ports",
			"event.action:(deny OR dropped OR blocked) AND destination.port:(4444 OR 1337 OR 3389)", 0},
		{"hunt-alert-web-scanner", "Web scanner user-agent",
			"user_agent.original.text:(sqlmap OR nmap OR nikto OR masscan)", 0},
	}
}

func provisionAlertRules(client *http.Client, kibanaURL string) {
	for _, r := range alertRules() {
		createAlertRule(client, kibanaURL, r)
	}
}

func createAlertRule(client *http.Client, kibanaURL string, r alertRule) {
	esQuery := fmt.Sprintf(`{"query":{"query_string":{"query":%q,"lenient":true}}}`, r.query)
	params := map[string]interface{}{
		"searchType":                 "esQuery",
		"esQuery":                    esQuery,
		"index":                      []string{IndexPrefix + "-*"},
		"timeField":                  "@timestamp",
		"threshold":                  []int{r.threshold},
		"thresholdComparator":        ">",
		"size":                       100,
		"timeWindowSize":             5,
		"timeWindowUnit":             "m",
		"aggType":                    "count",
		"groupBy":                    "all",
		"excludeHitsFromPreviousRun": true,
	}
	body, _ := json.Marshal(map[string]interface{}{
		"name":         r.name,
		"rule_type_id": ".es-query",
		"consumer":     "stackAlerts",
		"schedule":     map[string]string{"interval": "5m"},
		"params":       params,
		"actions":      []interface{}{},
		"tags":         []string{"analysishub", "hunt"},
	})
	req, _ := http.NewRequest(http.MethodPost, kibanaURL+"/api/alerting/rule/"+r.id, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("kbn-xsrf", "true")
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("logsearch: create alert rule %q failed: %v", r.name, err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusConflict {
		log.Printf("logsearch: alert rule %q ready (status %d)", r.name, resp.StatusCode)
	} else {
		log.Printf("logsearch: alert rule %q status %d", r.name, resp.StatusCode)
	}
}

// threatSearch is a prebuilt Discover saved search for a common threat pattern.
type threatSearch struct {
	id, title, query string
	columns          []string
}

func threatSearches() []threatSearch {
	return []threatSearch{
		{"hunt-ssh-bruteforce", "Threat: SSH brute-force",
			"event.action:ssh_login and event.outcome:failure",
			[]string{"@timestamp", "source.ip", "user.name", "host.name"}},
		{"hunt-win-logon-failed", "Threat: Windows failed logon (4625)",
			"event.code:4625",
			[]string{"@timestamp", "source.ip", "user.name", "winlog.computer_name"}},
		{"hunt-win-logon-success", "Windows successful logon (4624)",
			"event.code:4624",
			[]string{"@timestamp", "source.ip", "user.name", "winlog.computer_name"}},
		{"hunt-fw-c2-ports", "Threat: firewall block to C2-ish ports",
			"event.action:(deny or dropped or blocked) and destination.port:(4444 or 1337 or 3389 or 23 or 445)",
			[]string{"@timestamp", "source.ip", "destination.ip", "destination.port", "event.action"}},
		{"hunt-web-scanner-ua", "Threat: web scanner user-agents",
			"user_agent.original.text:(sqlmap or nmap or nikto or masscan or \"python-requests\")",
			[]string{"@timestamp", "source.ip", "url.original", "http.response.status_code", "user_agent.original"}},
		{"hunt-http-errors", "Web 4xx/5xx responses",
			"http.response.status_code >= 400",
			[]string{"@timestamp", "source.ip", "url.original", "http.response.status_code"}},
		{"hunt-powershell-child", "Threat: suspicious process / encoded PowerShell",
			"process.parent.name:powershell.exe or process.command_line.text:enc",
			[]string{"@timestamp", "host.name", "process.name", "process.command_line"}},
	}
}

func provisionThreatSearches(client *http.Client, kibanaURL string) {
	viewID := dataViewID(client, kibanaURL, IndexPrefix+"-*")
	if viewID == "" {
		log.Printf("logsearch: hunt-* data view not found, skipped threat rule pack")
		return
	}
	for _, ts := range threatSearches() {
		createSavedSearch(client, kibanaURL, viewID, ts)
	}
}

// dataViewID returns the id of the data view whose title matches pattern.
func dataViewID(client *http.Client, kibanaURL, pattern string) string {
	resp, err := client.Get(kibanaURL + "/api/data_views")
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	var body struct {
		DataView []struct {
			ID    string `json:"id"`
			Title string `json:"title"`
		} `json:"data_view"`
	}
	if json.NewDecoder(resp.Body).Decode(&body) != nil {
		return ""
	}
	for _, dv := range body.DataView {
		if dv.Title == pattern {
			return dv.ID
		}
	}
	return ""
}

func createSavedSearch(client *http.Client, kibanaURL, viewID string, ts threatSearch) {
	searchSource := map[string]interface{}{
		"query":        map[string]interface{}{"query": ts.query, "language": "kuery"},
		"filter":       []interface{}{},
		"indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index",
	}
	ssJSON, _ := json.Marshal(searchSource)
	payload := map[string]interface{}{
		"attributes": map[string]interface{}{
			"title":                 ts.title,
			"columns":               ts.columns,
			"sort":                  [][]string{{"@timestamp", "desc"}},
			"kibanaSavedObjectMeta": map[string]interface{}{"searchSourceJSON": string(ssJSON)},
		},
		"references": []map[string]interface{}{
			{"id": viewID, "name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern"},
		},
	}
	body, _ := json.Marshal(payload)
	// deterministic id so re-runs don't duplicate (409 = already exists = fine)
	req, _ := http.NewRequest(http.MethodPost, kibanaURL+"/api/saved_objects/search/"+ts.id, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("kbn-xsrf", "true")
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("logsearch: create saved search %q failed: %v", ts.title, err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusConflict {
		log.Printf("logsearch: saved search %q ready (status %d)", ts.title, resp.StatusCode)
	} else {
		log.Printf("logsearch: saved search %q status %d", ts.title, resp.StatusCode)
	}
}

func createDataView(client *http.Client, kibanaURL, name, pattern string) {
	body, _ := json.Marshal(map[string]interface{}{
		"data_view": map[string]interface{}{
			"title":         pattern,
			"name":          name,
			"timeFieldName": "@timestamp",
			"allowNoIndex":  true,
		},
		"override": false,
	})
	req, _ := http.NewRequest(http.MethodPost, kibanaURL+"/api/data_views/data_view", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("kbn-xsrf", "true")
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("logsearch: create kibana data view %q failed: %v", name, err)
		return
	}
	defer resp.Body.Close()
	// 200 = created, 400 = already exists — both fine.
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusBadRequest {
		log.Printf("logsearch: kibana data view %q (%s) ready (status %d)", name, pattern, resp.StatusCode)
	} else {
		log.Printf("logsearch: kibana data view %q unexpected status %d", name, resp.StatusCode)
	}
}
