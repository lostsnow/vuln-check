package vul

import (
	"fmt"
	"strings"
)

const (
	None                 = "none"
	CmdInjection         = "cmd-injection"
	CryptoWeakRandomness = "crypto-weak-randomness"
	CryptoBadCiphers     = "crypto-bad-ciphers"
	CryptoBadMac         = "crypto-bad-mac"
	CookieFlagsMissing   = "cookie-flags-missing"
)

const (
	AppWebGoat   = "webgoat"
	AppBenchmark = "benchmark"
	AppOpenRASP  = "openrasp"
)

type Vul struct {
	App          string `yaml:"app"`
	AppVersion   string `yaml:"appVersion"`
	URLPath      string `yaml:"urlPath"`
	VulType      string `yaml:"vulType"`
	ExpectResult string `yaml:"expectResult"`
	ActualResult string `yaml:"actualResult"`
	Description  string `yaml:"description"`
}

func ParseApp(s string) (string, error) {
	var app string
	switch strings.ToLower(s) {
	case AppWebGoat:
		app = AppWebGoat
	case AppBenchmark:
		app = AppBenchmark
	case AppOpenRASP:
		app = AppOpenRASP
	default:
		return "", fmt.Errorf("invalid app: %s", s)
	}

	return app, nil
}

func NormalizeUrlPath(path string) string {
	prefix := "org.owasp.benchmark.testcode."
	if strings.HasPrefix(strings.ToLower(path), "/benchmark/") {
		return path[strings.LastIndex(path, "/")+1:]
	} else if strings.HasPrefix(strings.ToLower(path), prefix) {
		l := len(prefix)
		return path[l : l+18]
	}

	return path
}
