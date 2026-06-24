//go:build windows
// +build windows

package parser

import (
	"encoding/json"
	"fmt"
	"golang.org/x/sys/windows/registry"
)

// RegEntry represents a single registry value
type RegEntry struct {
	Name  string      `json:"name"`
	Value interface{} `json:"value,omitempty"`
	Type  string      `json:"type,omitempty"`
	Error string      `json:"error,omitempty"`
}

// RegKeyData represents a parsed registry key with its values
type RegKeyData struct {
	KeyPath string     `json:"key_path"`
	Values  []RegEntry `json:"values"`
	Error   string     `json:"error,omitempty"`
}

// getRootKey converts a string to a registry.Key
func getRootKey(root string) (registry.Key, error) {
	switch root {
	case "HKCR", "HKEY_CLASSES_ROOT":
		return registry.CLASSES_ROOT, nil
	case "HKCU", "HKEY_CURRENT_USER":
		return registry.CURRENT_USER, nil
	case "HKLM", "HKEY_LOCAL_MACHINE":
		return registry.LOCAL_MACHINE, nil
	case "HKU", "HKEY_USERS":
		return registry.USERS, nil
	case "HKCC", "HKEY_CURRENT_CONFIG":
		return registry.CURRENT_CONFIG, nil
	default:
		return 0, fmt.Errorf("unknown root key: %s", root)
	}
}

// ParseRegistry reads a registry key and returns its values as JSON string
func ParseRegistry(root string, path string) (string, error) {
	rootKey, err := getRootKey(root)
	if err != nil {
		return "", err
	}

	k, err := registry.OpenKey(rootKey, path, registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return "", fmt.Errorf("open key %s\\%s: %w", root, path, err)
	}
	defer k.Close()

	names, err := k.ReadValueNames(-1)
	if err != nil {
		return "", fmt.Errorf("read value names: %w", err)
	}

	result := RegKeyData{
		KeyPath: fmt.Sprintf("%s\\%s", root, path),
		Values:  make([]RegEntry, 0, len(names)),
	}

	for _, name := range names {
		val, valType, err := k.GetValue(name, nil)
		if err != nil {
			result.Values = append(result.Values, RegEntry{Name: name, Error: err.Error()})
			continue
		}

		var strType string
		var actualVal interface{}

		// The GetValue in x/sys/windows/registry can read string/uint32/uint64/binary directly
		// but since we passed nil for the buffer it just tells us the size.
		// Let's use the typed getters.
		switch valType {
		case registry.SZ, registry.EXPAND_SZ:
			strType = "SZ"
			if valType == registry.EXPAND_SZ {
				strType = "EXPAND_SZ"
			}
			s, _, _ := k.GetStringValue(name)
			actualVal = s
		case registry.DWORD:
			strType = "DWORD"
			i, _, _ := k.GetIntegerValue(name)
			actualVal = i
		case registry.QWORD:
			strType = "QWORD"
			i, _, _ := k.GetIntegerValue(name)
			actualVal = i
		case registry.MULTI_SZ:
			strType = "MULTI_SZ"
			s, _, _ := k.GetStringsValue(name)
			actualVal = s
		case registry.BINARY:
			strType = "BINARY"
			b, _, _ := k.GetBinaryValue(name)
			actualVal = fmt.Sprintf("%x", b) // hex string for JSON
		default:
			strType = fmt.Sprintf("UNKNOWN_%d", valType)
			actualVal = fmt.Sprintf("<type %d len %d>", valType, val)
		}

		result.Values = append(result.Values, RegEntry{
			Name:  name,
			Value: actualVal,
			Type:  strType,
		})
	}

	jsonData, err := json.Marshal(result)
	if err != nil {
		return "", err
	}

	return string(jsonData), nil
}
