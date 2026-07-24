package sigma

import (
	"fmt"
	"strings"
)

// fieldAliases bridges the field namespaces a rule may be written against and
// the raw names the agent actually collects. SigmaHQ writes process_creation
// rules against Sysmon (Image, ParentImage, CommandLine, User) while the agent
// pulls Security 4688 events, whose EventData uses completely different names —
// without this table every upstream process rule is a guaranteed miss.
var fieldAliases = map[string][]string{
	// Sysmon name -> Security / other providers, and -> the Linux collector's
	// auditd field names so upstream linux rules resolve too.
	"image":             {"NewProcessName", "ProcessName", "Application", "SourceImage", "Executable", "exe"},
	"parentimage":       {"ParentProcessName", "CreatorProcessName", "ParentExe"},
	"commandline":       {"ProcessCommandLine", "CommandLine", "cmdline"},
	"parentcommandline": {"ParentProcessCommandLine"},
	"user":              {"SubjectUserName", "TargetUserName", "AccountName"},
	"processid":         {"NewProcessId", "ClientProcessId"},
	"originalfilename":  {"OriginalFileName"},
	"targetfilename":    {"FileName", "ObjectName", "RelativeTargetName"},
	"targetobject":      {"ObjectName"},
	"destinationip":     {"DestAddress", "DestinationAddress"},
	"destinationport":   {"DestPort", "DestinationPort"},
	"sourceip":          {"SourceAddress", "IpAddress", "ClientAddress"},
	"sourceport":        {"SourcePort"},
	"logonid":           {"SubjectLogonId", "TargetLogonId"},
	"computername":      {"Computer", "Hostname", "WorkstationName"},
	"servicename":       {"ServiceName"},
	"servicefilename":   {"ImagePath", "ServiceFileName"},
	"scriptblocktext":   {"ScriptBlock", "Payload"},

	// Security / other providers -> Sysmon, so a natively-4688 rule still works
	// when the host does have Sysmon installed.
	"newprocessname":     {"Image"},
	"parentprocessname":  {"ParentImage"},
	"processcommandline": {"CommandLine"},
	"subjectusername":    {"User"},
	"imagepath":          {"Image"},
}

// categoryEventIDs maps a Sigma logsource category to the Windows event IDs that
// can actually carry it. It is used to stop, say, a registry rule from being
// evaluated against a logon event — with ~3k synced rules and no logsource
// routing at all, unrelated single-field rules were a large false-positive
// source.
var categoryEventIDs = map[string][]string{
	"process_creation":     {"1", "4688"},
	"process_termination":  {"5", "4689"},
	"network_connection":   {"3", "5156", "5158"},
	"file_event":           {"11", "4663"},
	"file_delete":          {"23", "26"},
	"file_change":          {"2"},
	"image_load":           {"7"},
	"driver_load":          {"6"},
	"create_remote_thread": {"8"},
	"raw_access_thread":    {"9"},
	"process_access":       {"10"},
	"registry_event":       {"12", "13", "14", "4657"},
	"registry_add":         {"12", "4657"},
	"registry_set":         {"13", "4657"},
	"registry_delete":      {"12", "14", "4657"},
	"registry_rename":      {"14"},
	"pipe_created":         {"17", "18"},
	"wmi_event":            {"19", "20", "21"},
	"dns_query":            {"22"},
	"clipboard_capture":    {"24"},
	"process_tampering":    {"25"},
	"sysmon_error":         {"255"},
	"ps_script":            {"4104"},
	"ps_module":            {"4103"},
	"ps_classic_start":     {"400"},
}

// logsourceMatches reports whether a rule is applicable to an event. It is
// deliberately conservative: a rule is only rejected when the mismatch can be
// established positively, so an event we cannot classify still sees every rule.
func logsourceMatches(rule *Rule, event map[string]interface{}) bool {
	if len(rule.Logsource) == 0 {
		return true
	}

	product := strings.ToLower(rule.Logsource["product"])
	platform := eventPlatform(event)
	if product != "" {
		if platform != "" {
			// Both sides known: a linux rule must not be judged against a Windows
			// event and vice versa.
			if product != platform {
				return false
			}
		} else if product != "windows" {
			// An event we cannot classify comes from the Windows EVTX path, which
			// is the only source that does not label itself.
			return false
		}
	}

	category := strings.ToLower(rule.Logsource["category"])
	if platform == "linux" {
		// Linux events are categorised by name rather than by a numeric channel
		// id — the collector sets EventID to the category it observed.
		if category != "" {
			if got, found := lookupDirect(event, "EventID"); found {
				gotStr := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", got)))
				if gotStr != "" && gotStr != category {
					return false
				}
			}
		}
		return true
	}

	if ids, ok := categoryEventIDs[category]; ok {
		if got, found := lookupDirect(event, "EventID"); found {
			gotStr := strings.TrimSpace(fmt.Sprintf("%v", got))
			if gotStr != "" && !containsStr(ids, gotStr) {
				return false
			}
		}
	}

	// A rule bound to a specific provider (sysmon, powershell, …) should not fire
	// on a different one when we can see which it is. Generic channel names are
	// excluded: the agent reports the provider ("Service Control Manager"), not
	// the channel ("System"), so gating on those would reject valid rules.
	if service := strings.ToLower(rule.Logsource["service"]); service != "" && !genericChannels[service] {
		if chOK, matched := serviceMatches(service, event); chOK && !matched {
			return false
		}
	}
	return true
}

// eventPlatform reports which OS an event came from, or "" when it cannot be
// told. Only non-Windows collectors label themselves: the Windows EVTX path
// predates the field, so an unlabelled event is treated as Windows by callers.
func eventPlatform(event map[string]interface{}) string {
	if v, ok := lookupDirect(event, "Platform"); ok {
		if s := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", v))); s != "" {
			return s
		}
	}
	// Fallback for events that reach the engine without the explicit label: the
	// Linux collector records which log it read them from.
	if v, ok := lookupDirect(event, "Source"); ok {
		switch strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", v))) {
		case "auditd", "journald", "authlog":
			return "linux"
		}
	}
	return ""
}

// genericChannels are Windows log *channels* rather than provider names. Many
// providers write into them, so the name never appears in the event's provider.
var genericChannels = map[string]bool{
	"security": true, "system": true, "application": true, "setup": true,
}

// serviceMatches compares a logsource service against the event's channel and
// provider. chOK is false when the event carries neither, meaning "unknown —
// do not reject".
func serviceMatches(service string, event map[string]interface{}) (chOK bool, matched bool) {
	var haystack []string
	for _, key := range []string{"Channel", "Provider", "ProviderName", "LogName"} {
		if v, ok := lookupDirect(event, key); ok {
			if s := strings.ToLower(fmt.Sprintf("%v", v)); s != "" {
				haystack = append(haystack, s)
			}
		}
	}
	if len(haystack) == 0 {
		return false, false
	}
	// "sysmon" lives in Microsoft-Windows-Sysmon/Operational, "powershell" in
	// Microsoft-Windows-PowerShell/Operational, so substring matching is the
	// right granularity here.
	needle := strings.ReplaceAll(service, "_", "")
	for _, h := range haystack {
		if strings.Contains(strings.ReplaceAll(h, "-", ""), needle) || strings.Contains(h, service) {
			return true, true
		}
	}
	return true, false
}

func containsStr(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
