package hsts

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	https "github.com/coffeemakr/httpsify"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"

	filter "github.com/tmthrgd/go-filter"
)

const jsonURL = "https://chromium.googlesource.com/chromium/src/net/+/master/http/transport_security_state_static.json?format=TEXT"

func LoadHstsPreload() (*https.RuleCollection, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jsonURL, nil)
	if err != nil {
		return nil, err
	}

	log.Println("Loading preload JSON")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned unexpected %s status code", resp.Status)
	}

	br := filter.NewReader(
		base64.NewDecoder(base64.StdEncoding, resp.Body),
		func(line []byte) bool {
			line = bytes.TrimSpace(line)
			return !(len(line) >= 2 && string(line[:2]) == "//")
		})

	var rules struct {
		Entries []struct {
			Name string

			IncludeSubdomains bool `json:"include_subdomains"`

			Mode string
			//  "force-https" iff covered names should require HTTPS.
		}
	}
	if err := json.NewDecoder(br).Decode(&rules); err != nil {
		return nil, err
	}

	log.Println("Generating rules")
	sort.Slice(rules.Entries, func(i, j int) bool {
		ei, ej := rules.Entries[i], rules.Entries[j]
		if ei.IncludeSubdomains != ej.IncludeSubdomains {
			return ei.IncludeSubdomains
		}
		return ei.Name < ej.Name
	})

	var maxDots, dots int
	names := make([]string, 0, len(rules.Entries))
	includeSubdomainsNames := make([]string, 0, len(rules.Entries))
	for _, entry := range rules.Entries {
		if entry.Mode != "force-https" {
			continue
		}
		if entry.IncludeSubdomains {
			includeSubdomainsNames = append(includeSubdomainsNames, entry.Name)
		} else {
			names = append(names, entry.Name)
		}
		dots = strings.Count(entry.Name, ".")
		if dots > maxDots {
			maxDots = dots
		}
	}

	collection := https.NewRuleCollection()
	collection.AddSimpleHosts(includeSubdomainsNames, true)
	collection.AddSimpleHosts(names, false)
	return collection, nil
}