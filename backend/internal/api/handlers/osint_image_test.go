package handlers

import "testing"

func TestParseImageExtraction(t *testing.T) {
	reply := "Here you go:\n```json\n" + `{
		"ocr_text": "Send 0.5 BTC to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa or email pay@evil.com",
		"indicators": [
			{"type": "wallet", "value": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"},
			{"type": "email", "value": "pay@evil.com"},
			{"type": "email", "value": "pay@evil.com"},
			{"type": "domain", "value": "@@@"},
			{"type": "ip", "value": "8.8.8.8"}
		]
	}` + "\n```"

	ocr, cands := parseImageExtraction(reply)
	if ocr == "" {
		t.Error("expected OCR text to be parsed")
	}
	// Expect: wallet, email (deduped), ip = 3. The garbage "@@@" is dropped.
	if len(cands) != 3 {
		t.Fatalf("expected 3 validated candidates, got %d: %+v", len(cands), cands)
	}
	byType := map[string]string{}
	for _, c := range cands {
		byType[c.Type] = c.Value
	}
	if byType["wallet"] == "" || byType["email"] == "" || byType["ip"] != "8.8.8.8" {
		t.Errorf("unexpected candidate set: %+v", cands)
	}
}

func TestParseImageExtractionEmpty(t *testing.T) {
	_, cands := parseImageExtraction(`{"ocr_text":"nothing here","indicators":[]}`)
	if len(cands) != 0 {
		t.Errorf("expected no candidates, got %d", len(cands))
	}
}
