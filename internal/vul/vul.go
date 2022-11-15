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
	App           string `yaml:"app"`
	AppVersion    string `yaml:"appVersion"`
	URLPath       string `yaml:"urlPath"`
	VulType       string `yaml:"vulType"`
	VulScanResult string `yaml:"vulScanResult"`
	Description   string `yaml:"description"`
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

func IsNormalVal(vulType string) bool {
	if vulType == CryptoBadCiphers ||
			vulType == CryptoBadMac ||
			vulType == CryptoWeakRandomness ||
			vulType == CookieFlagsMissing {
		return true
	}
	return false
}

func NormalizeUrlPathForBenchmark(app, vulType, path string) string {
	if app != AppBenchmark {
		return path
	}
	if !IsNormalVal(vulType) {
		return path
	}

	return path
}
