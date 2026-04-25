package fingerprint

import (
	"regexp"
	"strings"
)

type FingerprintRule struct {
	Name        string
	Category    string
	HeaderRules []HeaderRule
	BodyRules   []BodyRule
	CVEs        []CVEInfo
}

type HeaderRule struct {
	Header string
	Regex  string
	re     *regexp.Regexp
}

type BodyRule struct {
	Regex string
	re    *regexp.Regexp
}

type CVEInfo struct {
	ID          string
	Severity    string
	Description string
}

type Fingerprint struct {
	Name     string
	Version  string
	Category string
	CVEs     []CVEInfo
}

func initHeaderRule(header, regex string) HeaderRule {
	hr := HeaderRule{
		Header: header,
		Regex:  regex,
	}
	if regex != "" {
		hr.re = regexp.MustCompile(regex)
	}
	return hr
}

func initBodyRule(regex string) BodyRule {
	br := BodyRule{Regex: regex}
	if regex != "" {
		br.re = regexp.MustCompile(regex)
	}
	return br
}

func (hr *HeaderRule) Match(headerValue string) (bool, string) {
	if hr.re == nil {
		return strings.Contains(strings.ToLower(headerValue), strings.ToLower(hr.Header)), ""
	}
	matches := hr.re.FindStringSubmatch(headerValue)
	if len(matches) > 0 {
		if len(matches) > 1 {
			return true, matches[1]
		}
		return true, ""
	}
	return false, ""
}

func (br *BodyRule) Match(body string) (bool, string) {
	if br.re == nil {
		return false, ""
	}
	matches := br.re.FindStringSubmatch(body)
	if len(matches) > 0 {
		if len(matches) > 1 {
			return true, matches[1]
		}
		return true, ""
	}
	return false, ""
}

func getDefaultFingerprints() []FingerprintRule {
	return []FingerprintRule{
		{
			Name:     "Nginx",
			Category: "Web Server",
			HeaderRules: []HeaderRule{
				initHeaderRule("Server", `nginx(?:/([\d.]+))?`),
			},
			CVEs: []CVEInfo{
				{ID: "CVE-2021-23017", Severity: "CRITICAL", Description: "DNS resolver off-by-one heap write"},
				{ID: "CVE-2019-20372", Severity: "HIGH", Description: "HTTP request smuggling"},
			},
		},
		{
			Name:     "Apache HTTPD",
			Category: "Web Server",
			HeaderRules: []HeaderRule{
				initHeaderRule("Server", `Apache(?:/([\d.]+))?`),
			},
			CVEs: []CVEInfo{
				{ID: "CVE-2021-41773", Severity: "CRITICAL", Description: "Path traversal and file disclosure"},
				{ID: "CVE-2021-42013", Severity: "CRITICAL", Description: "Path traversal bypass"},
			},
		},
		{
			Name:     "Microsoft-IIS",
			Category: "Web Server",
			HeaderRules: []HeaderRule{
				initHeaderRule("Server", `Microsoft-IIS(?:/([\d.]+))?`),
			},
			CVEs: []CVEInfo{
				{ID: "CVE-2017-7269", Severity: "HIGH", Description: "Buffer overflow in WebDAV"},
			},
		},
		{
			Name:     "Tomcat",
			Category: "Application Server",
			HeaderRules: []HeaderRule{
				initHeaderRule("Server", `Apache-Coyote/([\d.]+)`),
			},
			BodyRules: []BodyRule{
				initBodyRule(`Apache Tomcat(?:/([\d.]+))?`),
			},
			CVEs: []CVEInfo{
				{ID: "CVE-2022-22965", Severity: "CRITICAL", Description: "Spring4Shell RCE"},
				{ID: "CVE-2020-1938", Severity: "CRITICAL", Description: "Ghostcat AJP lfi"},
			},
		},
		{
			Name:     "Spring Framework",
			Category: "Framework",
			BodyRules: []BodyRule{
				initBodyRule(`Whitelabel Error Page`),
				initBodyRule(`<title>Error</title>.*spring`),
			},
			CVEs: []CVEInfo{
				{ID: "CVE-2022-22965", Severity: "CRITICAL", Description: "Spring4Shell RCE"},
				{ID: "CVE-2022-22963", Severity: "CRITICAL", Description: "Spring Cloud Function RCE"},
				{ID: "CVE-2022-22947", Severity: "HIGH", Description: "Spring Cloud Gateway RCE"},
			},
		},
		{
			Name:     "Django",
			Category: "Framework",
			HeaderRules: []HeaderRule{
				initHeaderRule("X-Frame-Options", ""),
			},
			BodyRules: []BodyRule{
				initBodyRule(`CSRF token missing or incorrect`),
				initBodyRule(`django.*error`),
			},
			CVEs: []CVEInfo{
				{ID: "CVE-2022-28346", Severity: "HIGH", Description: "SQL injection"},
			},
		},
		{
			Name:     "Express",
			Category: "Framework",
			HeaderRules: []HeaderRule{
				initHeaderRule("X-Powered-By", `Express`),
			},
		},
		{
			Name:     "PHP",
			Category: "Language",
			HeaderRules: []HeaderRule{
				initHeaderRule("X-Powered-By", `PHP(?:/([\d.]+))?`),
			},
			CVEs: []CVEInfo{
				{ID: "CVE-2019-11043", Severity: "HIGH", Description: "PHP-FPM RCE"},
			},
		},
		{
			Name:     "ASP.NET",
			Category: "Framework",
			HeaderRules: []HeaderRule{
				initHeaderRule("X-AspNet-Version", `([\d.]+)`),
				initHeaderRule("X-Powered-By", `ASP\.NET`),
			},
			CVEs: []CVEInfo{
				{ID: "CVE-2017-8759", Severity: "HIGH", Description: "SOAP WSDL parser code injection"},
			},
		},
		{
			Name:     "Shiro",
			Category: "Security Framework",
			HeaderRules: []HeaderRule{
				initHeaderRule("Set-Cookie", `rememberMe=delete`),
			},
			CVEs: []CVEInfo{
				{ID: "CVE-2016-4437", Severity: "CRITICAL", Description: "Shiro-550 RememberMe deserialization"},
				{ID: "CVE-2019-12422", Severity: "CRITICAL", Description: "Shiro-721 RememberMe padding oracle"},
			},
		},
		{
			Name:     "WebLogic",
			Category: "Application Server",
			HeaderRules: []HeaderRule{
				initHeaderRule("Server", `WebLogic`),
			},
			BodyRules: []BodyRule{
				initBodyRule(`WebLogic`),
				initBodyRule(`<title>Oracle WebLogic`),
			},
			CVEs: []CVEInfo{
				{ID: "CVE-2020-14882", Severity: "CRITICAL", Description: "Console takeover RCE"},
				{ID: "CVE-2017-10271", Severity: "CRITICAL", Description: "XMLDecoder deserialization"},
			},
		},
		{
			Name:     "Jenkins",
			Category: "CI/CD",
			HeaderRules: []HeaderRule{
				initHeaderRule("X-Jenkins", `([\d.]+)`),
			},
			BodyRules: []BodyRule{
				initBodyRule(`Jenkins`),
				initBodyRule(`<title>.*Jenkins`),
			},
			CVEs: []CVEInfo{
				{ID: "CVE-2019-1003000", Severity: "CRITICAL", Description: "Script Security sandbox bypass"},
				{ID: "CVE-2018-1999002", Severity: "HIGH", Description: "Arbitrary file read"},
			},
		},
		{
			Name:     "Drupal",
			Category: "CMS",
			HeaderRules: []HeaderRule{
				initHeaderRule("X-Generator", `Drupal`),
				initHeaderRule("X-Drupal-Cache", ""),
			},
			BodyRules: []BodyRule{
				initBodyRule(`Drupal\.settings`),
			},
			CVEs: []CVEInfo{
				{ID: "CVE-2018-7600", Severity: "CRITICAL", Description: "Drupalgeddon2 RCE"},
				{ID: "CVE-2019-6340", Severity: "CRITICAL", Description: "REST API RCE"},
			},
		},
		{
			Name:     "WordPress",
			Category: "CMS",
			BodyRules: []BodyRule{
				initBodyRule(`<meta name="generator" content="WordPress(?:\s+([\d.]+))?`),
				initBodyRule(`/wp-content/`),
				initBodyRule(`/wp-includes/`),
			},
			CVEs: []CVEInfo{
				{ID: "CVE-2019-8942", Severity: "HIGH", Description: "Author priv escalation"},
			},
		},
		{
			Name:     "ThinkPHP",
			Category: "Framework",
			HeaderRules: []HeaderRule{
				initHeaderRule("X-Powered-By", `ThinkPHP`),
			},
			BodyRules: []BodyRule{
				initBodyRule(`thinkphp`),
			},
			CVEs: []CVEInfo{
				{ID: "CVE-2019-9082", Severity: "CRITICAL", Description: "RCE via invoke function"},
			},
		},
		{
			Name:     "FastJSON",
			Category: "Library",
			BodyRules: []BodyRule{
				initBodyRule(`fastjson.*version`),
			},
			CVEs: []CVEInfo{
				{ID: "CVE-2022-25845", Severity: "CRITICAL", Description: "Deserialization RCE"},
			},
		},
		{
			Name:     "Node.js",
			Category: "Runtime",
			HeaderRules: []HeaderRule{
				initHeaderRule("X-Powered-By", `Express`),
			},
		},
		{
			Name:     "Vue.js",
			Category: "Frontend Framework",
			BodyRules: []BodyRule{
				initBodyRule(`data-v-[a-f0-9]+`),
				initBodyRule(`__vue__`),
			},
		},
		{
			Name:     "React",
			Category: "Frontend Framework",
			BodyRules: []BodyRule{
				initBodyRule(`_reactRootContainer`),
				initBodyRule(`data-reactroot`),
			},
		},
	}
}
