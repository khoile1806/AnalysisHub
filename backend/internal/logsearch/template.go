package logsearch

// indexTemplate returns the ECS index template applied to every hunt-* index.
// Fields are mapped explicitly (ip/long types) so IOC pivots and range/CIDR
// queries work; ignore_malformed keeps a bad value from dropping a whole doc.
func indexTemplate() map[string]interface{} {
	kwText := func() map[string]interface{} {
		return map[string]interface{}{
			"type": "keyword", "ignore_above": 1024,
			"fields": map[string]interface{}{"text": map[string]interface{}{"type": "text"}},
		}
	}
	props := map[string]interface{}{
		"@timestamp": map[string]interface{}{"type": "date"},
		"message":    map[string]interface{}{"type": "text"},
		"event": map[string]interface{}{"properties": map[string]interface{}{
			"code":     map[string]interface{}{"type": "keyword"},
			"action":   map[string]interface{}{"type": "keyword"},
			"category": map[string]interface{}{"type": "keyword"},
			"outcome":  map[string]interface{}{"type": "keyword"},
			"kind":     map[string]interface{}{"type": "keyword"},
			"provider": map[string]interface{}{"type": "keyword"},
			"severity": map[string]interface{}{"type": "keyword"},
		}},
		"source": map[string]interface{}{"properties": map[string]interface{}{
			"ip":     map[string]interface{}{"type": "ip"},
			"port":   map[string]interface{}{"type": "long"},
			"domain": map[string]interface{}{"type": "keyword"},
			"user":   map[string]interface{}{"properties": map[string]interface{}{"name": kwText()}},
		}},
		"destination": map[string]interface{}{"properties": map[string]interface{}{
			"ip":   map[string]interface{}{"type": "ip"},
			"port": map[string]interface{}{"type": "long"},
		}},
		"host": map[string]interface{}{"properties": map[string]interface{}{
			"name": map[string]interface{}{"type": "keyword"},
			"ip":   map[string]interface{}{"type": "ip"},
		}},
		"user": map[string]interface{}{"properties": map[string]interface{}{
			"name": kwText(), "domain": map[string]interface{}{"type": "keyword"},
		}},
		"process": map[string]interface{}{"properties": map[string]interface{}{
			"name":         kwText(),
			"executable":   kwText(),
			"command_line": kwText(),
			"pid":          map[string]interface{}{"type": "long"},
			"parent": map[string]interface{}{"properties": map[string]interface{}{
				"name": kwText(), "executable": kwText(),
			}},
		}},
		"network": map[string]interface{}{"properties": map[string]interface{}{
			"transport": map[string]interface{}{"type": "keyword"},
			"protocol":  map[string]interface{}{"type": "keyword"},
		}},
		"http": map[string]interface{}{"properties": map[string]interface{}{
			"request":  map[string]interface{}{"properties": map[string]interface{}{"method": map[string]interface{}{"type": "keyword"}}},
			"response": map[string]interface{}{"properties": map[string]interface{}{"status_code": map[string]interface{}{"type": "long"}}},
		}},
		"url":        map[string]interface{}{"properties": map[string]interface{}{"original": kwText()}},
		"user_agent": map[string]interface{}{"properties": map[string]interface{}{"original": kwText()}},
		"file": map[string]interface{}{"properties": map[string]interface{}{
			"path": kwText(), "name": map[string]interface{}{"type": "keyword"},
		}},
		"registry": map[string]interface{}{"properties": map[string]interface{}{"path": kwText(), "value": kwText()}},
		"hunt": map[string]interface{}{"properties": map[string]interface{}{
			"case":              map[string]interface{}{"type": "keyword"},
			"log_type":          map[string]interface{}{"type": "keyword"},
			"category":          map[string]interface{}{"type": "keyword"},
			"source_file":       map[string]interface{}{"type": "keyword"},
			"timestamp_missing": map[string]interface{}{"type": "boolean"},
		}},
	}

	return map[string]interface{}{
		"index_patterns": []string{IndexPrefix + "-*"},
		"template": map[string]interface{}{
			"settings": map[string]interface{}{
				"number_of_shards":                 1,
				"number_of_replicas":               0,
				"index.mapping.total_fields.limit": 8000,
				"index.mapping.ignore_malformed":   true,
				"index.refresh_interval":           "5s",
			},
			"mappings": map[string]interface{}{
				"properties": props,
				"dynamic_templates": []interface{}{
					map[string]interface{}{"ports_as_long": map[string]interface{}{
						"match": "*port", "match_mapping_type": "long",
						"mapping": map[string]interface{}{"type": "long"},
					}},
					map[string]interface{}{"strings_as_keyword": map[string]interface{}{
						"match_mapping_type": "string",
						"mapping": map[string]interface{}{
							"type": "keyword", "ignore_above": 1024,
							"fields": map[string]interface{}{"text": map[string]interface{}{"type": "text"}},
						},
					}},
				},
			},
		},
	}
}
