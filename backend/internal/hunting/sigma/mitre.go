package sigma

import "strings"

// sigmaTacticNames maps Sigma's ATT&CK tactic tags (attack.<tactic>) to the
// canonical MITRE tactic display name.
var sigmaTacticNames = map[string]string{
	"reconnaissance":       "Reconnaissance",
	"resource_development": "Resource Development",
	"initial_access":       "Initial Access",
	"execution":            "Execution",
	"persistence":          "Persistence",
	"privilege_escalation": "Privilege Escalation",
	"defense_evasion":      "Defense Evasion",
	"credential_access":    "Credential Access",
	"discovery":            "Discovery",
	"lateral_movement":     "Lateral Movement",
	"collection":           "Collection",
	"command_and_control":  "Command and Control",
	"exfiltration":         "Exfiltration",
	"impact":               "Impact",
}

// mitreFromTags extracts MITRE ATT&CK technique IDs and tactic names from a
// rule's Sigma tags. Techniques are tagged as attack.tNNNN[.NNN]; tactics as
// attack.<tactic_name>. Group/software tags (attack.gNNNN / attack.sNNNN) and
// any non-attack tags are ignored.
func mitreFromTags(tags []string) (techniques, tactics []string) {
	seenTech, seenTac := map[string]bool{}, map[string]bool{}
	for _, raw := range tags {
		t := strings.ToLower(strings.TrimSpace(raw))
		if !strings.HasPrefix(t, "attack.") {
			continue
		}
		v := strings.TrimPrefix(t, "attack.")
		if v == "" {
			continue
		}
		// Technique: t<digit>… (optionally with a .NNN sub-technique).
		if v[0] == 't' && len(v) > 1 && v[1] >= '0' && v[1] <= '9' {
			id := strings.ToUpper(v)
			if !seenTech[id] {
				seenTech[id] = true
				techniques = append(techniques, id)
			}
			continue
		}
		// Group (g<digit>) / software (s<digit>) — not a tactic; skip.
		if (v[0] == 'g' || v[0] == 's') && len(v) > 1 && v[1] >= '0' && v[1] <= '9' {
			continue
		}
		if name, ok := sigmaTacticNames[v]; ok && !seenTac[name] {
			seenTac[name] = true
			tactics = append(tactics, name)
		}
	}
	return techniques, tactics
}
