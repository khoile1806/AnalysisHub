package sigma

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Alert represents a triggered Sigma rule against an event.
type Alert struct {
	RuleTitle       string                 `json:"rule_title"`
	RuleLevel       string                 `json:"rule_level"`
	RuleDescription string                 `json:"rule_description"`
	Event           map[string]interface{} `json:"event"`
}

// Engine loads and evaluates Sigma rules.
type Engine struct {
	rules []*Rule
	mu    sync.RWMutex
}

var (
	DefaultEngine *Engine
	once          sync.Once
)

// Init loads rules from the specified directory.
func Init(rulesDir string) {
	once.Do(func() {
		DefaultEngine = &Engine{}
		DefaultEngine.LoadDirectory(rulesDir)
	})
}

// LoadDirectory loads all .yml and .yaml files in a directory recursively.
func (e *Engine) LoadDirectory(dir string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.rules = make([]*Rule, 0)
	
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".yml" || ext == ".yaml" {
			rule, err := LoadRule(path)
			if err == nil && rule != nil {
				e.rules = append(e.rules, rule)
			}
		}
		return nil
	})

	if err != nil {
		log.Printf("Sigma engine failed to walk directory %s: %v", dir, err)
	} else {
		log.Printf("Sigma engine loaded %d rules from %s", len(e.rules), dir)
	}
}

// Scan takes an array of JSON objects (events) and evaluates them against all rules.
func (e *Engine) Scan(jsonData string) ([]Alert, error) {
	var events []map[string]interface{}
	if err := json.Unmarshal([]byte(jsonData), &events); err != nil {
		// Try parsing as single object
		var singleEvent map[string]interface{}
		if err2 := json.Unmarshal([]byte(jsonData), &singleEvent); err2 != nil {
			return nil, fmt.Errorf("invalid json event data")
		}
		events = append(events, singleEvent)
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	var alerts []Alert
	for _, event := range events {
		for _, rule := range e.rules {
			if MatchEvent(rule, event) {
				alerts = append(alerts, Alert{
					RuleTitle:       rule.Title,
					RuleLevel:       rule.Level,
					RuleDescription: rule.Description,
					Event:           event,
				})
			}
		}
	}

	return alerts, nil
}
