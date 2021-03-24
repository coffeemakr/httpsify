package httpseverywhere

import (
	"encoding/xml"
	"fmt"
	https "github.com/coffeemakr/httpsify"
	"io/ioutil"
	"strings"
)

// XmlRule - structure used to import rewrite data from xml
type XmlRule struct {
	From string `xml:"from,attr"`
	To   string `xml:"to,attr"`
}

func (r XmlRule) Parse() (https.Rule, error) {
	if r.IsStandardRule() {
		return https.StandardRule, nil
	} else {
		return &https.RegexRule{
			From: r.From,
			To:   r.To,
		}, nil
	}
}

func (r XmlRule) IsStandardRule() bool {
	return r.From == "^http:" && r.To == "https:"
}

// XmlTarget - structure used to import target data from xml
type XmlTarget struct {
	Host string `xml:"host,attr"`
}

// XmlExclusion - structure used to import exclusion data from xml
type XmlExclusion struct {
	Pattern string `xml:"pattern,attr"`
}

// XmlText - structure used to import testing data from xml
type XmlText struct {
	URL string `xml:"url,attr"`
}

// XmlRuleset - represents an xml rule file
type XmlRuleset struct {
	Name       string         `xml:"name,attr"`
	Disabled   string         `xml:"default_off,attr"`
	Platform   string         `xml:"platform,attr"`
	Targets    []XmlTarget    `xml:"target"`
	Rules      []XmlRule      `xml:"rule"`
	Exclusions []XmlExclusion `xml:"exclusion"`
	Tests      []XmlText      `xml:"test"`
}

func (r XmlRuleset) ParseRules() (*https.Ruleset, error) {
	globalRules := make([]https.Rule, 0, len(r.Rules)+len(r.Exclusions))

	// Exclusion must go in the list before other rule
	for _, rawExclusion := range r.Exclusions {
		exclusion := new(https.ExclusionRule)
		exclusion.Match = rawExclusion.Pattern
		globalRules = append(globalRules, exclusion)
	}

	for _, rule := range r.Rules {
		parsed, err := rule.Parse()
		if err != nil {
			return nil, err
		}
		globalRules = append(globalRules, parsed)
	}

	var combinedRule https.Rule
	if len(globalRules) == 1 {
		combinedRule = globalRules[0]
	} else {
		combinedRule = https.RuleList(globalRules)
	}

	targets := make([]string, 0, 0)
	subdomainTargets := make([]string, 0, 0)

	for _, target := range r.Targets {
		if strings.HasPrefix(target.Host, "*.") {
			subdomainTargets = append(subdomainTargets, target.Host[2:])
		} else {
			targets = append(targets, target.Host)
		}
	}
	return &https.Ruleset{
		Targets:          targets,
		SubdomainTargets: subdomainTargets,
		Rule:             combinedRule,
	}, nil
}

func LoadRules(RulePath string, channel chan *XmlRuleset) error {
	defer close(channel)
	fileList, err := ioutil.ReadDir(RulePath)
	if err != nil {
		return err
	}
	for _, fileInfo := range fileList {
		if fileInfo.IsDir() || !strings.HasSuffix(fileInfo.Name(), ".xml") {
			continue
		}

		xmldata, err := ioutil.ReadFile(RulePath + "/" + fileInfo.Name())
		if err != nil {
			return fmt.Errorf("error reading file. [%s]", fileInfo.Name())
		}

		rules := new(XmlRuleset)
		if err := xml.Unmarshal(xmldata, rules); err != nil {
			fmt.Printf("Error occured in file [%s] :: [%s]\n", fileInfo.Name(), err.Error())
			continue
		}
		channel <- rules
	}
	return nil
}

// Parse - reads rule xml files and constructs their in-memory representation
func Parse(RulePath string) (*https.RuleCollection, error) {
	channel := make(chan *XmlRuleset)
	var err error
	go func() {
		err = LoadRules(RulePath, channel)
	}()
	collection := https.NewRuleCollection()
	for data := range channel {
		rule, err := data.ParseRules()
		if err != nil {
			return nil, fmt.Errorf("error while parsing rule %s: %s", data.Name, err)
		}
		collection.AddRuleset(rule)
	}
	if err != nil {
		return nil, err
	}
	return collection, nil
}
