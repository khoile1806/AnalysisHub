package handlers

import "testing"

func TestHayHasBounded_IP(t *testing.T) {
	cases := []struct {
		hay, needle string
		want        bool
	}{
		{"conn to 1.2.3.4 established", "1.2.3.4", true}, // exact
		{"1.2.3.4:443", "1.2.3.4", true},                 // port suffix ok
		{"src=1.2.3.4\ndst=8.8.8.8", "1.2.3.4", true},    // field boundary
		{"blocked 11.2.3.44 today", "1.2.3.4", false},    // substring of longer IP
		{"route 1.2.3.40/24", "1.2.3.4", false},          // trailing digit
		{"200.1.2.3.4", "1.2.3.4", false},                // leading dot+digit
	}
	for _, c := range cases {
		if got := hayHasBounded(c.hay, c.needle, true); got != c.want {
			t.Errorf("hayHasBounded(%q,%q,ip)=%v want %v", c.hay, c.needle, got, c.want)
		}
	}
}

func TestHayHasBounded_Domain(t *testing.T) {
	cases := []struct {
		hay, needle string
		want        bool
	}{
		{"beacon to evil.com now", "evil.com", true},     // exact
		{"host: sub.evil.com", "evil.com", true},         // sub-domain matches parent
		{"https://evil.com/path", "evil.com", true},      // scheme+path boundary
		{"evil.com:8080", "evil.com", true},              // port suffix
		{"totally notevil.com site", "evil.com", false},  // prefixed different domain
		{"visit evil.community page", "evil.com", false}, // longer TLD-ish suffix
	}
	for _, c := range cases {
		if got := hayHasBounded(c.hay, c.needle, false); got != c.want {
			t.Errorf("hayHasBounded(%q,%q,domain)=%v want %v", c.hay, c.needle, got, c.want)
		}
	}
}
