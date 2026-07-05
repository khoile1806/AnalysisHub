package logsearch

import (
	"bytes"
	"encoding/json"
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
