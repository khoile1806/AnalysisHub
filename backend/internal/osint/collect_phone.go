package osint

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/forensichub/backend/internal/models"
)

// phoneCountry maps an E.164 country calling code to a human-readable country
// name. Codes are 1-3 digits; lookup tries the longest prefix first. This is
// a dependency-free substitute for a full libphonenumber metadata bundle -
// carrier / line-type detection requires the optional NumVerify collector.
var phoneCountry = map[string]string{
	"1": "North America (NANP)", "7": "Russia / Kazakhstan",
	"20": "Egypt", "27": "South Africa", "30": "Greece", "31": "Netherlands",
	"32": "Belgium", "33": "France", "34": "Spain", "36": "Hungary",
	"39": "Italy", "40": "Romania", "41": "Switzerland", "43": "Austria",
	"44": "United Kingdom", "45": "Denmark", "46": "Sweden", "47": "Norway",
	"48": "Poland", "49": "Germany", "51": "Peru", "52": "Mexico",
	"53": "Cuba", "54": "Argentina", "55": "Brazil", "56": "Chile",
	"57": "Colombia", "58": "Venezuela", "60": "Malaysia", "61": "Australia",
	"62": "Indonesia", "63": "Philippines", "64": "New Zealand", "65": "Singapore",
	"66": "Thailand", "81": "Japan", "82": "South Korea", "84": "Vietnam",
	"86": "China", "90": "Turkey", "91": "India", "92": "Pakistan",
	"93": "Afghanistan", "94": "Sri Lanka", "95": "Myanmar", "98": "Iran",
	"211": "South Sudan", "212": "Morocco", "213": "Algeria", "216": "Tunisia",
	"233": "Ghana", "234": "Nigeria", "251": "Ethiopia", "254": "Kenya",
	"255": "Tanzania", "256": "Uganda", "260": "Zambia", "263": "Zimbabwe",
	"351": "Portugal", "352": "Luxembourg", "353": "Ireland", "354": "Iceland",
	"355": "Albania", "356": "Malta", "357": "Cyprus", "358": "Finland",
	"359": "Bulgaria", "370": "Lithuania", "371": "Latvia", "372": "Estonia",
	"380": "Ukraine", "381": "Serbia", "385": "Croatia", "386": "Slovenia",
	"420": "Czechia", "421": "Slovakia", "423": "Liechtenstein",
	"852": "Hong Kong", "853": "Macau", "855": "Cambodia", "856": "Laos",
	"880": "Bangladesh", "886": "Taiwan", "960": "Maldives", "961": "Lebanon",
	"962": "Jordan", "963": "Syria", "964": "Iraq", "965": "Kuwait",
	"966": "Saudi Arabia", "967": "Yemen", "968": "Oman", "971": "United Arab Emirates",
	"972": "Israel", "973": "Bahrain", "974": "Qatar", "975": "Bhutan",
	"976": "Mongolia", "977": "Nepal", "992": "Tajikistan", "993": "Turkmenistan",
	"994": "Azerbaijan", "995": "Georgia", "996": "Kyrgyzstan", "998": "Uzbekistan",
}

// onlyDigits returns the digit characters of s in order.
func onlyDigits(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// lookupCountryCode finds the longest matching calling code in digits and
// returns (code, countryName). Returns ("","") when no prefix matches.
func lookupCountryCode(digits string) (string, string) {
	for n := 3; n >= 1; n-- {
		if len(digits) <= n {
			continue
		}
		prefix := digits[:n]
		if name, ok := phoneCountry[prefix]; ok {
			return prefix, name
		}
	}
	return "", ""
}

// -- Static metadata (dependency-free) -----------------------------------------

// collectPhoneMeta derives country, calling code and E.164 form from the
// number using a static country-code table.
func collectPhoneMeta(_ context.Context, env *collectorEnv) ([]models.OsintFinding, error) {
	raw := strings.TrimSpace(env.target)
	digits := onlyDigits(raw)
	// A leading "00" is the international access prefix - equivalent to "+".
	digits = strings.TrimPrefix(digits, "00")
	if digits == "" {
		return nil, fmt.Errorf("no digits in phone number")
	}

	var out []models.OsintFinding
	out = append(out, newFinding("phone_meta", "identity", "E.164 format", "+"+digits))

	code, country := lookupCountryCode(digits)
	if code != "" {
		out = append(out, newFinding("phone_meta", "identity", "Country calling code", "+"+code))
		out = append(out, newFinding("phone_meta", "identity", "Country", country))
		national := digits[len(code):]
		if national != "" {
			out = append(out, newFinding("phone_meta", "identity", "National number", national))
		}
	} else {
		f := newFinding("phone_meta", "identity", "Country",
			"could not be determined - number may lack a country code")
		f.Severity = "low"
		out = append(out, f)
	}

	// E.164 allows at most 15 digits; fewer than 8 is implausible for a real
	// internationally-dialable number.
	lenFinding := newFinding("phone_meta", "identity", "Plausibility",
		fmt.Sprintf("%d digit(s)", len(digits)))
	if len(digits) < 8 || len(digits) > 15 {
		lenFinding.Value += " - outside the E.164 8-15 digit range"
		lenFinding.Severity = "low"
	} else {
		lenFinding.Value += " - within the E.164 range"
	}
	out = append(out, lenFinding)
	return out, nil
}

// -- NumVerify (optional key) --------------------------------------------------

type numVerifyResponse struct {
	Valid               bool   `json:"valid"`
	InternationalFormat string `json:"international_format"`
	CountryName         string `json:"country_name"`
	Location            string `json:"location"`
	Carrier             string `json:"carrier"`
	LineType            string `json:"line_type"`
	Success             *bool  `json:"success"` // present only on error responses
	Error               struct {
		Info string `json:"info"`
	} `json:"error"`
}

// collectNumVerify resolves carrier and line type via NumVerify (apilayer).
// Needs OSINT_NUMVERIFY_API_KEY.
func collectNumVerify(ctx context.Context, env *collectorEnv) ([]models.OsintFinding, error) {
	if env.keys.NumVerify == "" {
		return nil, errNoAPIKey
	}
	number := onlyDigits(env.target)
	u := env.cfg.APINumVerifyURL + "?access_key=" +
		url.QueryEscape(env.keys.NumVerify) + "&number=" + url.QueryEscape(number)
	var r numVerifyResponse
	status, err := httpGetJSON(ctx, nil, u, nil, &r)
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("NumVerify returned HTTP %d", status)
	}
	if r.Success != nil && !*r.Success {
		info := r.Error.Info
		if info == "" {
			info = "request rejected"
		}
		return nil, fmt.Errorf("NumVerify: %s", info)
	}

	var out []models.OsintFinding
	validity := newFinding("numverify", "identity", "Validity (NumVerify)", "valid")
	if !r.Valid {
		validity.Value = "invalid"
		validity.Severity = "low"
	}
	out = append(out, validity)
	if r.CountryName != "" {
		out = append(out, newFinding("numverify", "identity", "Country (NumVerify)",
			joinNonEmpty(" - ", r.CountryName, r.Location)))
	}
	if r.Carrier != "" {
		out = append(out, newFinding("numverify", "identity", "Carrier", r.Carrier))
	}
	if r.LineType != "" {
		out = append(out, newFinding("numverify", "identity", "Line type", r.LineType))
	}
	return out, nil
}
