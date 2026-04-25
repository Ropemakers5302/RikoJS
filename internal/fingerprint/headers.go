package fingerprint

import "strings"

func (s *Scanner) analyzeHeaders(headers map[string]string) {
	if server, ok := headers["Server"]; ok {
		server = strings.ToLower(server)
		switch {
		case strings.Contains(server, "nginx"):
			s.mu.Lock()
			s.results = append(s.results, Fingerprint{
				Name:     "Nginx",
				Category: "Web Server",
				CVEs:     CVEDatabase["nginx"],
			})
			s.mu.Unlock()
		case strings.Contains(server, "apache"):
			s.mu.Lock()
			s.results = append(s.results, Fingerprint{
				Name:     "Apache HTTPD",
				Category: "Web Server",
				CVEs:     CVEDatabase["apache"],
			})
			s.mu.Unlock()
		}
	}

	if poweredBy, ok := headers["X-Powered-By"]; ok {
		poweredBy = strings.ToLower(poweredBy)
		switch {
		case strings.Contains(poweredBy, "php"):
			s.mu.Lock()
			s.results = append(s.results, Fingerprint{
				Name:     "PHP",
				Category: "Language",
			})
			s.mu.Unlock()
		case strings.Contains(poweredBy, "asp"):
			s.mu.Lock()
			s.results = append(s.results, Fingerprint{
				Name:     "ASP.NET",
				Category: "Framework",
			})
			s.mu.Unlock()
		case strings.Contains(poweredBy, "express"):
			s.mu.Lock()
			s.results = append(s.results, Fingerprint{
				Name:     "Express.js",
				Category: "Framework",
			})
			s.mu.Unlock()
		}
	}
}
