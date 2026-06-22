package osint

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// AccountDetector represents a method to detect account existence
type AccountDetector struct {
	Name           string
	Type           string // "email" or "phone"
	CheckFunc      func(ctx context.Context, target string) (bool, float64, error)
	BaseConfidence float64
}

// DetectEmailAccountViaSearch performs multiple checks to find email accounts
func DetectEmailAccountViaSearch(ctx context.Context, email string) ([]map[string]interface{}, error) {
	var findings []map[string]interface{}

	// Check GitHub - look for profile
	if exists, conf := checkGitHubEmail(ctx, email); exists && conf > 0.6 {
		findings = append(findings, map[string]interface{}{
			"platform":   "GitHub",
			"email":      email,
			"exists":     true,
			"confidence": conf,
			"url":        fmt.Sprintf("https://github.com/search?q=%s", email),
		})
	}

	// Check ProtonMail - look for recovery
	if exists, conf := checkProtonMailEmail(ctx, email); exists && conf > 0.6 {
		findings = append(findings, map[string]interface{}{
			"platform":   "ProtonMail",
			"email":      email,
			"exists":     true,
			"confidence": conf,
			"url":        "https://account.proton.me/",
		})
	}

	// Check Gmail by looking at public profiles
	if exists, conf := checkGmailEmail(ctx, email); exists && conf > 0.6 {
		findings = append(findings, map[string]interface{}{
			"platform":   "Gmail",
			"email":      email,
			"exists":     true,
			"confidence": conf,
			"url":        "https://myaccount.google.com/",
		})
	}

	// Check HaveIBeenPwned
	if exists, conf := checkHIBPEmail(ctx, email); exists && conf > 0.6 {
		findings = append(findings, map[string]interface{}{
			"platform":   "HaveIBeenPwned",
			"email":      email,
			"exists":     true,
			"confidence": conf,
			"url":        "https://haveibeenpwned.com/",
		})
	}

	// Check Linkedin - via search
	if exists, conf := checkLinkedInEmail(ctx, email); exists && conf > 0.6 {
		findings = append(findings, map[string]interface{}{
			"platform":   "LinkedIn",
			"email":      email,
			"exists":     true,
			"confidence": conf,
			"url":        fmt.Sprintf("https://www.linkedin.com/search/results/all/?keywords=%s", email),
		})
	}

	// Check Facebook - via search
	if exists, conf := checkFacebookEmail(ctx, email); exists && conf > 0.6 {
		findings = append(findings, map[string]interface{}{
			"platform":   "Facebook",
			"email":      email,
			"exists":     true,
			"confidence": conf,
			"url":        fmt.Sprintf("https://www.facebook.com/search/top/?q=%s", email),
		})
	}

	return findings, nil
}

// Check functions - each returns (accountExists, confidence, error)

func checkGitHubEmail(ctx context.Context, email string) (bool, float64) {
	// GitHub password reset endpoint
	return checkPasswordReset(ctx, "https://github.com/password_reset", "email", email,
		[]string{"check your email", "if this email address is associated"},
		[]string{"couldn't find", "not found"},
		0.85)
}

func checkProtonMailEmail(ctx context.Context, email string) (bool, float64) {
	// ProtonMail password reset - actually send HTTP request
	return checkPasswordReset(ctx, "https://account.proton.me/api/auth/password/reset", "email", email,
		[]string{"reset link sent", "check your email"},
		[]string{"user not found", "invalid email"},
		0.80)
}

func checkGmailEmail(ctx context.Context, email string) (bool, float64) {
	// Gmail account recovery - check if account exists via recovery flow
	return checkPasswordReset(ctx, "https://accounts.google.com/signin/recovery", "email", email,
		[]string{"found your account", "recovery options", "account recovery"},
		[]string{"couldn't find", "couldn't locate"},
		0.75)
}

func checkHIBPEmail(ctx context.Context, email string) (bool, float64) {
	// Have I Been Pwned API
	url := fmt.Sprintf("https://haveibeenpwned.com/api/v3/breachedaccount?account=%s&truncateResponse=false", email)
	resp, err := makeRequest(ctx, "GET", url, "", 10)
	if err != nil {
		return false, 0
	}
	defer resp.Body.Close()

	// If status 200, account has breaches
	if resp.StatusCode == 200 {
		return true, 0.90
	}
	// 404 = not breached but may exist
	if resp.StatusCode == 404 {
		return false, 0.3
	}
	return false, 0
}

func checkLinkedInEmail(ctx context.Context, email string) (bool, float64) {
	// LinkedIn search - public API
	return checkPasswordReset(ctx, "https://www.linkedin.com/voyager/api/search/hits", "email", email,
		[]string{"keyword_values", "profile"},
		[]string{"no results", "not found"},
		0.75)
}

func checkFacebookEmail(ctx context.Context, email string) (bool, float64) {
	// Facebook - via login check
	return checkPasswordReset(ctx, "https://www.facebook.com/login/identify/?ctx=recover", "email", email,
		[]string{"found the account", "verification", "code"},
		[]string{"couldn't find", "no account"},
		0.70)
}

// Password reset checker - generic function
func checkPasswordReset(ctx context.Context, url, fieldName, value string,
	successMarkers, notFoundMarkers []string, baseConf float64) (bool, float64) {

	payload := fieldName + "=" + value
	resp, err := makeRequest(ctx, "POST", url, payload, 15)
	if err != nil {
		return false, 0
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return false, 0
	}

	bodyText := strings.ToLower(string(body))

	// Check success markers
	for _, marker := range successMarkers {
		if strings.Contains(bodyText, strings.ToLower(marker)) {
			return true, baseConf
		}
	}

	// Check not-found markers
	for _, marker := range notFoundMarkers {
		if strings.Contains(bodyText, strings.ToLower(marker)) {
			return false, baseConf * 0.3
		}
	}

	// Check status code
	if resp.StatusCode >= 500 {
		return false, 0
	}
	if resp.StatusCode == 429 {
		return false, 0
	}
	if resp.StatusCode == 200 && baseConf > 0.5 {
		// Likely account exists if we get 200 after POST
		return true, baseConf * 0.6
	}

	return false, 0
}

// Helper to make HTTP requests
func makeRequest(ctx context.Context, method, url, body string, timeout int) (*http.Response, error) {
	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequestWithContext(ctx, method, url, strings.NewReader(body))
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36")
	if method == "POST" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	return client.Do(req)
}
