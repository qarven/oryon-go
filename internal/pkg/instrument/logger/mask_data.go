package logger

import (
	"encoding/json"
	"strings"
)

func maskAny(val any, maskKeys map[string]struct{}) (any, bool) {
	switch value := val.(type) {
	case map[string]any:
		return maskData(value, maskKeys), true
	case map[string]string:
		converted := make(map[string]any, len(value))
		for k, v2 := range value {
			converted[k] = v2
		}

		return maskData(converted, maskKeys), true
	case []any:
		return maskData(value, maskKeys), true
	default:
		return nil, false
	}
}

func maskJSONString(payload string, maskKeys map[string]struct{}) (string, bool) {
	payload = strings.TrimLeft(payload, " \t\r\n")
	if payload == "" || (payload[0] != '{' && payload[0] != '[') {
		return "", false
	}

	var jsonBody any

	err := json.Unmarshal([]byte(payload), &jsonBody)
	if err != nil {
		return "", false
	}

	masked := maskData(jsonBody, maskKeys)

	maskedBytes, err := json.Marshal(masked)
	if err == nil {
		return string(maskedBytes), true
	}

	return "", false
}

func maskJSONBytes(payload []byte, maskKeys map[string]struct{}) (string, bool) {
	if len(payload) == 0 {
		return "", false
	}

	var jsonBody any

	err := json.Unmarshal(payload, &jsonBody)
	if err != nil {
		return "", false
	}

	masked := maskData(jsonBody, maskKeys)

	maskedBytes, err := json.Marshal(masked)
	if err == nil {
		return string(maskedBytes), true
	}

	return "", false
}

func maskData(value any, maskKeys map[string]struct{}) any {
	switch val := value.(type) {
	case map[string]any:
		masked := make(map[string]any, len(val))
		for k, v2 := range val {
			if _, found := maskKeys[strings.ToLower(k)]; found {
				masked[k] = "***"
			} else {
				masked[k] = maskData(v2, maskKeys)
			}
		}

		return masked
	case []any:
		res := make([]any, len(val))
		for i, v2 := range val {
			res[i] = maskData(v2, maskKeys)
		}

		return res
	default:
		return value
	}
}
