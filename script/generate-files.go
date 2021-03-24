package main

import (
	"flag"
	fmt "fmt"
	"github.com/coffeemakr/httpsify/hsts"
	"github.com/coffeemakr/httpsify/httpseverywhere"
	"log"
	"os"
)

func writeHostsFile(hosts []string, filename string) error {
	fp, err := os.Create(filename)
	defer fp.Close()
	if err != nil {
		return err
	}
	for _, host := range hosts {
		fmt.Fprintln(fp, host)
	}
	return nil
}

func main() {
	var rulesPath string
	var hostsFile string
	var subdomainsFile string
	flag.StringVar(&rulesPath, "http-everywhere-rules", "", "Path to the rules")
	flag.StringVar(&hostsFile, "domains-out", "", "Path to the rules")
	flag.StringVar(&subdomainsFile, "subdomains-out", "", "Path to the rules")

	log.Println("Loading https everywhere...")
	rules, err := httpseverywhere.Parse(rulesPath)
	if err != nil {
		log.Fatalln(err)
	}
	log.Println("Loading hsts...")
	hstsRules, err := hsts.LoadHstsPreload()
	if err != nil {
		log.Fatalln(err)
	}

	rules.Add(hstsRules)
	hstsRules = nil

	err = writeHostsFile(rules.SimpleSubdomainTargets(), subdomainsFile)
	if err != nil {
		log.Fatalln(err)
	}
	err = writeHostsFile(rules.SimpleTargets(), hostsFile)
	if err != nil {
		log.Fatalln(err)
	}
}
