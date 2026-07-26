package redact

import (
	"reflect"
	"regexp"
	"strings"
)

var (
	urlCredentials      = regexp.MustCompile(`(?i)(https?://)[^/@\s]+@`)
	sensitiveQuery      = regexp.MustCompile(`(?i)([?&](?:api[_-]?key|access[_-]?token|auth|key|rpc[_-]?key|token|secret|password)=)[^&\s]+`)
	privateKey          = regexp.MustCompile(`(?i)((?:private[_ -]?key|secret[_ -]?key)\s*[:=]\s*)(?:0x)?[0-9a-f]{64}`)
	seedPhrase          = regexp.MustCompile(`(?i)((?:seed[_ -]?phrase|mnemonic)\s*[:=][ \t]*)[a-z]+(?:[ \t]+[a-z]+){11,23}`)
	bearerToken         = regexp.MustCompile(`(?i)(authorization\s*[:=]\s*bearer\s+)[^\s,;]+`)
	secretEnvironment   = regexp.MustCompile(`(?im)(^|[\s,;])((?:api[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key|secret(?:[_-]?(?:access)?[_-]?key)?|token|password)\s*=\s*)[^\s,;]+`)
	secretJSON          = regexp.MustCompile(`(?i)("(?:api[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key|secret|token|password)"\s*:\s*")[^"]*(")`)
	ansiEscape          = regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]`)
	posixHomePath       = regexp.MustCompile(`(?i)(/(?:home|users)/)[^/\s]+/`)
	windowsUserHomePath = regexp.MustCompile(`(?i)([a-z]:\\users\\)[^\\\s]+\\`)
)

func String(value string) string {
	value = strings.ToValidUTF8(value, "\uFFFD")
	value = ansiEscape.ReplaceAllString(value, "")
	value = urlCredentials.ReplaceAllString(value, `${1}[REDACTED]@`)
	value = sensitiveQuery.ReplaceAllString(value, `${1}[REDACTED]`)
	value = privateKey.ReplaceAllString(value, `${1}[REDACTED]`)
	value = seedPhrase.ReplaceAllString(value, `${1}[REDACTED]`)
	value = bearerToken.ReplaceAllString(value, `${1}[REDACTED]`)
	value = secretEnvironment.ReplaceAllString(value, `${1}${2}[REDACTED]`)
	value = secretJSON.ReplaceAllString(value, `${1}[REDACTED]${2}`)
	value = posixHomePath.ReplaceAllString(value, `${1}[REDACTED]/`)
	value = windowsUserHomePath.ReplaceAllString(value, `${1}[REDACTED]\`)
	value = strings.Map(func(character rune) rune {
		if character == '\n' || character == '\r' || character == '\t' {
			return character
		}
		if character < 0x20 || character == 0x7f {
			return -1
		}
		return character
	}, value)
	return value
}

func Strings(value any) {
	sanitize(reflect.ValueOf(value))
}

func sanitize(value reflect.Value) {
	if !value.IsValid() {
		return
	}
	switch value.Kind() {
	case reflect.Pointer:
		if !value.IsNil() {
			sanitize(value.Elem())
		}
	case reflect.Interface:
		if !value.IsNil() {
			sanitize(value.Elem())
		}
	case reflect.Struct:
		for index := 0; index < value.NumField(); index++ {
			field := value.Field(index)
			if field.CanSet() || field.Kind() != reflect.Struct {
				sanitize(field)
			}
		}
	case reflect.Slice:
		for index := 0; index < value.Len(); index++ {
			sanitize(value.Index(index))
		}
	case reflect.Map:
		iterator := value.MapRange()
		for iterator.Next() {
			mapValue := iterator.Value()
			copyValue := reflect.New(mapValue.Type()).Elem()
			copyValue.Set(mapValue)
			sanitize(copyValue)
			value.SetMapIndex(iterator.Key(), copyValue)
		}
	case reflect.String:
		if value.CanSet() {
			value.SetString(String(value.String()))
		}
	}
}
