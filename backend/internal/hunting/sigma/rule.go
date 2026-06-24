package sigma

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Rule represents a parsed Sigma rule.
type Rule struct {
	Title       string
	Description string
	Level       string
	Logsource   map[string]string
	Detection   map[string]interface{}
	Condition   string
	
	filepath    string
}

// LoadRule parses a Sigma YAML file.
func LoadRule(path string) (*Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var raw map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	r := &Rule{
		filepath: path,
	}

	if t, ok := raw["title"].(string); ok { r.Title = t }
	if d, ok := raw["description"].(string); ok { r.Description = d }
	if l, ok := raw["level"].(string); ok { r.Level = l }

	if ls, ok := raw["logsource"].(map[string]interface{}); ok {
		r.Logsource = make(map[string]string)
		for k, v := range ls {
			r.Logsource[k] = fmt.Sprintf("%v", v)
		}
	}

	if det, ok := raw["detection"].(map[string]interface{}); ok {
		r.Detection = det
		if cond, ok := det["condition"].(string); ok {
			r.Condition = cond
		}
	}

	return r, nil
}
