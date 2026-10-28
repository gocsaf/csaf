package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

type entries = map[string]map[string]string

func main() {
	var names, suffixes [2]string
	var documents [2]map[string]entries
	for i, filename := range os.Args[1:3] {
		names[i], _, _ = strings.Cut(filepath.Base(filename), "-names")
		data, _ := os.ReadFile(filename)
		_ = json.Unmarshal(data, &documents[i])
	}
	if names[0] == names[1] {
		panic("names must differ")
	}
	width := max(len(names[0]), len(names[1]))
	for i, name := range names {
		suffixes[i] = "_" + name + strings.Repeat("_", width-len(name))
	}

	merged := map[string]entries{}
	anomaly := map[string]map[string]entries{names[0]: {}, names[1]: {}}
	for _, kind := range []string{"advisory", "provider", "aggregator"} {
		for i, name := range names {
			anomaly[name][kind] = entries{}
			for path, entry := range documents[i][kind] {
				if _, exists := documents[1-i][kind][path]; !exists {
					anomaly[name][kind][path] = entry
				}
			}
		}
		merged[kind] = entries{}
		for path := range documents[0][kind] {
			if _, exists := documents[1][kind][path]; !exists {
				continue
			}
			merged[kind][path] = map[string]string{}
			for i, document := range documents {
				for field, value := range document[kind][path] {
					merged[kind][path][field+suffixes[i]] = value
				}
			}
		}
	}

	output := struct {
		Advisory   entries                       `json:"advisory"`
		Provider   entries                       `json:"provider"`
		Aggregator entries                       `json:"aggregator"`
		Anomaly    map[string]map[string]entries `json:"anomaly"`
	}{merged["advisory"], merged["provider"], merged["aggregator"], anomaly}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	_ = encoder.Encode(output)
}
