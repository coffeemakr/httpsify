package httpsify

var preloadedRules *RuleCollection

// Rewrite rewrites urls using the HSTS preload list and https-everywhere rules.
func Rewrite(url string) (string, error) {
	url, _ = preloadedRules.Rewrite(url)
	return url, nil
}
