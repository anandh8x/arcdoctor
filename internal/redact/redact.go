package redact

import "regexp"

var (
	urlCredentials = regexp.MustCompile(`(?i)(https?://)[^/@\s]+@`)
	sensitiveQuery = regexp.MustCompile(`(?i)([?&](?:api[_-]?key|access[_-]?token|token|secret|password)=)[^&\s]+`)
)

func String(value string) string {
	value = urlCredentials.ReplaceAllString(value, `${1}[REDACTED]@`)
	return sensitiveQuery.ReplaceAllString(value, `${1}[REDACTED]`)
}
