package jsanalyser

import (
	"regexp"
	"strings"
)

type HAEEngine struct {
	rules []HAERule
}

type HAERule struct {
	Name     string
	Pattern  *regexp.Regexp
	Severity string
	Category string
}

func NewHAEEngine() *HAEEngine {
	return &HAEEngine{
		rules: initDefaultRules(),
	}
}

func initDefaultRules() []HAERule {
	rules := []HAERule{
		{
			Name:     "AWS Access Key",
			Pattern:  regexp.MustCompile(`(?i)(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`),
			Severity: "HIGH",
			Category: "CloudCredential",
		},
		{
			Name:     "AWS Secret Key",
			Pattern:  regexp.MustCompile(`(?i)(?:aws)?_?secret_?(?:access)?_?key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?`),
			Severity: "HIGH",
			Category: "CloudCredential",
		},
		{
			Name:     "Google API Key",
			Pattern:  regexp.MustCompile(`(?i)AIza[0-9A-Za-z\-_]{35}`),
			Severity: "HIGH",
			Category: "APIKey",
		},
		{
			Name:     "Google OAuth",
			Pattern:  regexp.MustCompile(`(?i)[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`),
			Severity: "HIGH",
			Category: "OAuthCredential",
		},
		{
			Name:     "GitHub Token",
			Pattern:  regexp.MustCompile(`(?i)(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}`),
			Severity: "HIGH",
			Category: "APIToken",
		},
		{
			Name:     "Slack Token",
			Pattern:  regexp.MustCompile(`(?i)xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}`),
			Severity: "HIGH",
			Category: "APIToken",
		},
		{
			Name:     "Stripe API Key",
			Pattern:  regexp.MustCompile(`(?i)sk_live_[0-9a-zA-Z]{24}`),
			Severity: "HIGH",
			Category: "APIKey",
		},
		{
			Name:     "Stripe Publishable Key",
			Pattern:  regexp.MustCompile(`(?i)pk_live_[0-9a-zA-Z]{24}`),
			Severity: "MEDIUM",
			Category: "APIKey",
		},
		{
			Name:     "JWT Token",
			Pattern:  regexp.MustCompile(`eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*`),
			Severity: "MEDIUM",
			Category: "AuthToken",
		},
		{
			Name:     "Private Key",
			Pattern:  regexp.MustCompile(`-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----`),
			Severity: "CRITICAL",
			Category: "CryptographicKey",
		},
		{
			Name:     "Generic Secret",
			Pattern:  regexp.MustCompile(`(?i)(?:secret|api[_-]?key|apikey|access[_-]?key|auth[_-]?key|token|password|passwd|pwd)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_\-\.]{8,})['\"]?`),
			Severity: "MEDIUM",
			Category: "GenericSecret",
		},
		{
			Name:     "Authorization Header",
			Pattern:  regexp.MustCompile(`(?i)authorization\s*[:=]\s*['\"]?(bearer|basic|token)\s+['\"]?([A-Za-z0-9_\-\.]+)['\"]?`),
			Severity: "MEDIUM",
			Category: "AuthToken",
		},
		{
			Name:     "Database Connection String",
			Pattern:  regexp.MustCompile(`(?i)(?:mysql|postgres|mongodb|redis)://[^\s'"<>]+`),
			Severity: "HIGH",
			Category: "ConnectionString",
		},
		{
			Name:     "Firebase URL",
			Pattern:  regexp.MustCompile(`(?i)https://[a-z0-9-]+\.firebaseio\.com`),
			Severity: "MEDIUM",
			Category: "CloudURL",
		},
		{
			Name:     "Heroku API Key",
			Pattern:  regexp.MustCompile(`(?i)[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}`),
			Severity: "MEDIUM",
			Category: "APIKey",
		},
	}
	return rules
}

func (h *HAEEngine) Scan(content string) []Secret {
	secrets := make([]Secret, 0)
	lines := strings.Split(content, "\n")

	for lineNum, line := range lines {
		for _, rule := range h.rules {
			matches := rule.Pattern.FindAllString(line, -1)
			for _, match := range matches {
				secrets = append(secrets, Secret{
					Type:     rule.Name,
					Value:    match,
					Line:     lineNum + 1,
					Severity: rule.Severity,
				})
			}
		}
	}

	return secrets
}

func (h *HAEEngine) AddRule(name, pattern, severity string) error {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}
	h.rules = append(h.rules, HAERule{
		Name:     name,
		Pattern:  re,
		Severity: severity,
	})
	return nil
}
