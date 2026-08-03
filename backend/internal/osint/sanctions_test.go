package osint

import (
	"strings"
	"testing"
)

// A trimmed SDN fixture in the real legacy schema: one individual with two crypto
// addresses + an a.k.a., and one entity. Namespaced root, to prove local-name
// matching survives the xmlns.
const sdnFixture = `<?xml version="1.0" encoding="UTF-8"?>
<sdnList xmlns="http://www.un.org/sanctions/1.0">
  <sdnEntry>
    <uid>12345</uid>
    <firstName>Ivan</firstName>
    <lastName>Petrov</lastName>
    <sdnType>Individual</sdnType>
    <programList><program>CYBER2</program></programList>
    <akaList>
      <aka><type>a.k.a.</type><firstName>Vanya</firstName><lastName>Petrov</lastName></aka>
    </akaList>
    <idList>
      <id><uid>1</uid><idType>Digital Currency Address - XBT</idType><idNumber>1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2</idNumber></id>
      <id><uid>2</uid><idType>Digital Currency Address - ETH</idType><idNumber>0xAbC0000000000000000000000000000000000001</idNumber></id>
      <id><uid>3</uid><idType>Passport</idType><idNumber>X999</idNumber></id>
    </idList>
  </sdnEntry>
  <sdnEntry>
    <uid>67890</uid>
    <lastName>Evil Corp LLC</lastName>
    <sdnType>Entity</sdnType>
    <programList><program>SDGT</program></programList>
  </sdnEntry>
</sdnList>`

func mustParseSDN(t *testing.T) *sdnIndex {
	t.Helper()
	idx, err := parseSDN(strings.NewReader(sdnFixture))
	if err != nil {
		t.Fatalf("parseSDN: %v", err)
	}
	return idx
}

func TestParseSDN_CryptoAddresses(t *testing.T) {
	idx := mustParseSDN(t)

	// BTC address (case-sensitive base58) is indexed lower-cased for lookup.
	if rec := idx.byAddr[strings.ToLower("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2")]; rec == nil {
		t.Error("BTC address not indexed")
	} else if rec.Name != "Ivan Petrov" {
		t.Errorf("BTC owner: got %q want %q", rec.Name, "Ivan Petrov")
	}

	// ETH lookups must be case-insensitive.
	if rec := idx.byAddr["0xabc0000000000000000000000000000000000001"]; rec == nil {
		t.Error("ETH address not indexed case-insensitively")
	}

	// A non-crypto identifier (passport) must NOT enter the address index.
	if _, ok := idx.byAddr["x999"]; ok {
		t.Error("passport number leaked into the crypto-address index")
	}
}

func TestParseSDN_Names(t *testing.T) {
	idx := mustParseSDN(t)

	// Primary name (normalised) resolves the individual.
	if recs := idx.byName[normName("Ivan Petrov")]; len(recs) == 0 {
		t.Error("primary name not indexed")
	}
	// The a.k.a. resolves too.
	if recs := idx.byName[normName("Vanya Petrov")]; len(recs) == 0 {
		t.Error("aka name not indexed")
	}
	// Entity whose whole name lives in lastName.
	if recs := idx.byName[normName("Evil Corp LLC")]; len(recs) == 0 {
		t.Error("entity name not indexed")
	} else if recs[0].Type != "Entity" {
		t.Errorf("entity type: got %q", recs[0].Type)
	}
}

func TestNormName(t *testing.T) {
	cases := map[string]string{
		"  Ivan   PETROV ": "ivan petrov",
		"John\tDoe":        "john doe",
	}
	for in, want := range cases {
		if got := normName(in); got != want {
			t.Errorf("normName(%q) = %q, want %q", in, got, want)
		}
	}
}
