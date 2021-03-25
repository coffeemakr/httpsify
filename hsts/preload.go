package hsts

import (
	"github.com/chromium/hstspreload/chromium/preloadlist"
	https "github.com/coffeemakr/httpsify"
	"strings"
)

func LoadHstsPreload() (*https.RuleCollection, error) {
	preloadList, err := preloadlist.NewFromLatest()
	if err != nil {
		return nil, err
	}

	names := make([]string, 0, len(preloadList.Entries))
	includeSubdomainsNames := make([]string, 0, len(preloadList.Entries))

	var maxDots, dots int
	for _, entry := range preloadList.Entries {
		if entry.Mode != "force-https" {
			continue
		}
		if entry.IncludeSubDomains {
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