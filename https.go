package httpsify

import (
	"fmt"
	"github.com/dlclark/regexp2"
	"golang.org/x/net/idna"
	"log"
	"strings"
	"time"
)

type Rule interface {
	Rewrite(url string) (string, bool)
}

type RuleList []Rule

func (r RuleList) Rewrite(url string) (string, bool) {
	for _, rule := range r {
		result, ok := rule.Rewrite(url)
		if ok {
			return result, true
		}
	}
	return url, false
}

type StandardRuleType struct {
}

func (d StandardRuleType) Rewrite(url string) (string, bool) {
	const prefix = "http:"
	if strings.HasPrefix(url, prefix) {
		return "https:" + url[len(prefix):], true
	}
	return url, false
}

var StandardRule = &StandardRuleType{}

// RuleCollection - internal representation of the rules rulesets
type RuleCollection struct {
	targets                map[string]Rule
	subdomainTargets       map[string]Rule
	simpleTargets          map[string]bool
	simpleSubdomainTargets map[string]bool
	maxDots                int
	maxLength              int
}

func (c RuleCollection) SimpleTargets() []string {
	targets := make([]string, 0, len(c.simpleTargets))
	for host, _ := range c.simpleTargets {
		targets = append(targets, host)
	}
	return targets
}

func (c RuleCollection) SimpleSubdomainTargets() []string {
	targets := make([]string, 0, len(c.simpleSubdomainTargets))
	for host, _ := range c.simpleSubdomainTargets {
		targets = append(targets, host)
	}
	return targets
}

func NewRuleCollection() *RuleCollection {
	return &RuleCollection{
		targets:                make(map[string]Rule),
		subdomainTargets:       make(map[string]Rule),
		simpleTargets:          make(map[string]bool),
		simpleSubdomainTargets: make(map[string]bool),
	}
}

func tokenizeURL(in string) (scheme, domain, site string, e error) {
	/// detach the scheme part

	if strings.HasPrefix(in, "http://") {
		scheme = "http"
		in = in[7:]
	} else {
		e = fmt.Errorf("protocol is not supported")
		return
	}
	/// now detach the site part, or rather anything, that comes after the `/' token
	si := strings.Index(in, "/")
	if si > -1 {
		site = in[si+1:]
		in = in[:si]
	}
	domain = in
	return
}

func NthLastIndexOf(s string, b byte, n int) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == b {
			n--
			if n == 0 {
				return i
			}
		}
	}
	return -1
}

func (h *RuleCollection) Rewrite(url string) (string, bool) {
	_, host, _, err := tokenizeURL(url)
	if err != nil {
		return url, false
	}

	host, err = idna.ToASCII(host)
	if err != nil {
		return "", false
	}
	host = strings.ToLower(host)
	extraDotIndex := NthLastIndexOf(host, '.', 4)
	if extraDotIndex >= 0 {
		// Target name is longer than any of the registered hosts
		host = host[extraDotIndex:]
	} else {
		if h.simpleTargets[host] {
			return StandardRule.Rewrite(url)
		}
		rule, ok := h.targets[host]
		if ok {
			return rule.Rewrite(url)
		}
	}

	for {
		if h.simpleSubdomainTargets[host] {
			return StandardRule.Rewrite(url)
		}
		rule, ok := h.subdomainTargets[host]
		if ok {
			return rule.Rewrite(url)
		}
		idx := strings.IndexByte(host, '.')
		if idx < 0 {
			break
		}
		host = host[idx+1:]
	}
	return url, false
}

func (h *RuleCollection) AddRule(rule Rule, host string, includeSubdomains bool) {
	if h.targets == nil {
		h.targets = make(map[string]Rule)
	}
	if h.subdomainTargets == nil {
		h.subdomainTargets = make(map[string]Rule)
	}
	dotCount := strings.Count(host, ".")
	if dotCount > h.maxDots {
		h.maxDots = dotCount
	}
	if len(host) > h.maxLength {
		h.maxLength = len(host)
	}
	if rule == StandardRule {
		if includeSubdomains {
			h.simpleSubdomainTargets[host] = true
		} else {
			h.simpleTargets[host] = true
		}
	} else {
		if includeSubdomains {
			h.subdomainTargets[host] = rule
		} else {
			h.targets[host] = rule
		}
	}
}

func (h *RuleCollection) AddRuleset(ruleset *Ruleset) {
	for _, host := range ruleset.Targets {
		h.AddRule(ruleset.Rule, host, false)
	}
}

func (h *RuleCollection) AddSimpleHosts(hosts []string, includeSubdomains bool) {
	for _, host := range hosts {
		if includeSubdomains {
			h.simpleSubdomainTargets[host] = true
		} else {
			h.simpleTargets[host] = true
		}
	}
}

func (h *RuleCollection) Add(rules *RuleCollection) {
	for target, rule := range rules.targets {
		h.targets[target] = rule
	}
	for target, rule := range rules.subdomainTargets {
		h.subdomainTargets[target] = rule
	}
	for target, val := range rules.simpleSubdomainTargets {
		h.simpleSubdomainTargets[target] = val
	}
	for target, val := range rules.simpleTargets {
		h.simpleTargets[target] = val
	}
	if rules.maxDots > h.maxDots {
		h.maxDots = rules.maxDots
	}
	if rules.maxLength > h.maxLength {
		h.maxLength = rules.maxLength
	}
}

type Ruleset struct {
	Targets          []string
	SubdomainTargets []string
	Rule             Rule
}

type ExclusionRule struct {
	Match string
}

type SimpleExclusion string

func (e ExclusionRule) Rewrite(url string) (string, bool) {
	pattern, err := regexp2.Compile(e.Match, regexp2.None)
	if err != nil {
		log.Println("Failed to compile exclusion")
		return url, true
	}
	if match, err := pattern.MatchString(url); err != nil && match {
		return url, true
	} else {
		return url, false
	}
}

type RegexRule struct {
	From   string
	To     string
	regexp *regexp2.Regexp
}

func (r RegexRule) Rewrite(url string) (string, bool) {
	if r.regexp == nil {
		var err error
		r.regexp, err = regexp2.Compile(r.From, regexp2.None)
		r.regexp.MatchTimeout = time.Second
		if err != nil {
			log.Println("Failed to parse rule regex", r.From, err)
			return url, false
		}
	}

	if match, err := r.regexp.MatchString(url); err == nil && match {
		result, err := r.regexp.Replace(url, r.To, -1, -1)
		if err != nil {
			return url, false
		}
		return result, true
	} else {
		return url, false
	}
}
