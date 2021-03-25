// +build !generate

package httpsify

import "github.com/coffeemakr/httpsify/simple"

// Rewrite rewrites urls using the HSTS preload list and https-everywhere rules.
func Rewrite(url string) (string, error) {
	url, _ = simple.SimpleRules.Rewrite(url)
	return url, nil
}