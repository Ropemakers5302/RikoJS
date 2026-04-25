package fingerprint

import "strings"

var CVEDatabase = map[string][]CVEInfo{
	"nginx": {
		{ID: "CVE-2021-23017", Severity: "CRITICAL", Description: "DNS resolver off-by-one heap write RCE"},
		{ID: "CVE-2019-20372", Severity: "HIGH", Description: "HTTP request smuggling"},
		{ID: "CVE-2013-4547", Severity: "HIGH", Description: "Directory traversal via malformed URI"},
		{ID: "CVE-2019-9511", Severity: "HIGH", Description: "HTTP/2 DoS via window size manipulation"},
		{ID: "CVE-2019-9513", Severity: "HIGH", Description: "HTTP/2 DoS via request cancellation flood"},
	},
	"apache": {
		{ID: "CVE-2021-41773", Severity: "CRITICAL", Description: "Path traversal and file disclosure"},
		{ID: "CVE-2021-42013", Severity: "CRITICAL", Description: "Path traversal bypass CVE-2021-41773"},
		{ID: "CVE-2020-1934", Severity: "HIGH", Description: "SSRF in mod_proxy"},
		{ID: "CVE-2019-10098", Severity: "HIGH", Description: "XSS in mod_rewrite"},
		{ID: "CVE-2018-17199", Severity: "HIGH", Description: "Session fixation in mod_session"},
	},
	"tomcat": {
		{ID: "CVE-2022-22965", Severity: "CRITICAL", Description: "Spring4Shell RCE (class loader manipulation)"},
		{ID: "CVE-2020-1938", Severity: "CRITICAL", Description: "Ghostcat - AJP file read/inclusion"},
		{ID: "CVE-2019-0232", Severity: "CRITICAL", Description: "CGI argument injection RCE"},
		{ID: "CVE-2020-9484", Severity: "HIGH", Description: "Session persistence deserialization"},
		{ID: "CVE-2021-30639", Severity: "HIGH", Description: "Denial of service via h2c"},
	},
	"spring": {
		{ID: "CVE-2022-22965", Severity: "CRITICAL", Description: "Spring4Shell - RCE via data binding"},
		{ID: "CVE-2022-22963", Severity: "CRITICAL", Description: "Spring Cloud Function SpEL RCE"},
		{ID: "CVE-2022-22947", Severity: "HIGH", Description: "Spring Cloud Gateway Actuator RCE"},
		{ID: "CVE-2022-22950", Severity: "HIGH", Description: "DoS via SpEL expression"},
		{ID: "CVE-2021-22118", Severity: "HIGH", Description: "Local privilege escalation"},
	},
	"shiro": {
		{ID: "CVE-2016-4437", Severity: "CRITICAL", Description: "Shiro-550 RememberMe AES deserialization"},
		{ID: "CVE-2019-12422", Severity: "CRITICAL", Description: "Shiro-721 RememberMe padding oracle"},
		{ID: "CVE-2020-1957", Severity: "HIGH", Description: "Authentication bypass in Shiro 1.5.2"},
		{ID: "CVE-2020-11989", Severity: "HIGH", Description: "Authentication bypass via path traversal"},
		{ID: "CVE-2020-13933", Severity: "HIGH", Description: "Authentication bypass in Shiro 1.6.0"},
	},
	"weblogic": {
		{ID: "CVE-2020-14882", Severity: "CRITICAL", Description: "Console takeover RCE"},
		{ID: "CVE-2020-14750", Severity: "CRITICAL", Description: "Authentication bypass for CVE-2020-14882"},
		{ID: "CVE-2017-10271", Severity: "CRITICAL", Description: "XMLDecoder deserialization RCE"},
		{ID: "CVE-2019-2725", Severity: "CRITICAL", Description: "Async response service deserialization"},
		{ID: "CVE-2018-2628", Severity: "CRITICAL", Description: "T3 protocol deserialization RCE"},
	},
	"fastjson": {
		{ID: "CVE-2022-25845", Severity: "CRITICAL", Description: "AutoType bypass deserialization RCE"},
		{ID: "CVE-2017-18349", Severity: "CRITICAL", Description: "Deserialization RCE"},
	},
	"thinkphp": {
		{ID: "CVE-2019-9082", Severity: "CRITICAL", Description: "RCE via invoke function"},
		{ID: "CVE-2018-20062", Severity: "CRITICAL", Description: "RCE via Request class"},
		{ID: "CVE-2019-16313", Severity: "HIGH", Description: "Remote code execution"},
	},
	"drupal": {
		{ID: "CVE-2018-7600", Severity: "CRITICAL", Description: "Drupalgeddon2 - RCE"},
		{ID: "CVE-2018-7602", Severity: "CRITICAL", Description: "Drupalgeddon3 - RCE"},
		{ID: "CVE-2019-6340", Severity: "CRITICAL", Description: "REST API deserialization RCE"},
		{ID: "CVE-2019-11831", Severity: "HIGH", Description: "Phar deserialization"},
	},
	"jenkins": {
		{ID: "CVE-2019-1003000", Severity: "CRITICAL", Description: "Script Security sandbox bypass RCE"},
		{ID: "CVE-2019-1003005", Severity: "CRITICAL", Description: "Pipeline: Groovy sandbox bypass"},
		{ID: "CVE-2018-1999002", Severity: "HIGH", Description: "Arbitrary file read via CLI"},
		{ID: "CVE-2019-10392", Severity: "HIGH", Description: "Git plugin RCE"},
	},
	"php": {
		{ID: "CVE-2019-11043", Severity: "HIGH", Description: "PHP-FPM buffer underflow RCE"},
		{ID: "CVE-2012-1823", Severity: "CRITICAL", Description: "CGI parameter injection RCE"},
	},
}

func GetCVEsFor(tech string) []CVEInfo {
	if cves, ok := CVEDatabase[strings.ToLower(tech)]; ok {
		return cves
	}
	return nil
}
