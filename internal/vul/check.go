package vul

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type CheckResult struct {
	MatchedVuls      []Vul
	MissingResult    []Vul
	WrongScanResults []ScanResult
	NoneVuls         []Vul
	NoSupportVuls    []Vul
}

func Check(vulMap map[string]Vul, scanResultMap map[string]ScanResult) (*CheckResult, error) {
	var missingVuls []Vul
	var matchedVuls []Vul
	var wrongScanResults []ScanResult
	var noneVuls []Vul
	var noSupportVuls []Vul

	for k, v := range vulMap {
		if v.VulScanResult == ScanNone {
			noSupportVuls = append(noneVuls, v)
			continue
		}

		if v.VulScanResult == ScanNoSupport {
			noSupportVuls = append(noSupportVuls, v)
			continue
		}

		if _, ok := scanResultMap[k]; ok {
			matchedVuls = append(matchedVuls, v)
		} else {
			missingVuls = append(missingVuls, v)
		}
	}

	for k, v := range scanResultMap {
		if _, ok := vulMap[k]; !ok {
			wrongScanResults = append(wrongScanResults, v)
		}
	}

	return &CheckResult{
		MatchedVuls:      matchedVuls,
		MissingResult:    missingVuls,
		WrongScanResults: wrongScanResults,
		NoneVuls:         noneVuls,
		NoSupportVuls:    noSupportVuls,
	}, nil
}

func ParseVulYaml(yamlPath, app string) (map[string]Vul, error) {
	var vs []Vul
	f, err := os.ReadFile(yamlPath)
	if err != nil {
		return nil, fmt.Errorf("read yaml file %s failed: %w", yamlPath, err)
	}
	err = yaml.Unmarshal(f, &vs)
	if err != nil {
		return nil, fmt.Errorf("unmarshal yaml file %s failed: %w", yamlPath, err)
	}

	// fmt.Println(vs)
	m := make(map[string]Vul, len(vs))
	for _, v := range vs {
		if app != strings.ToLower(v.App) {
			continue
		}
		key := v.URLPath + "::" + v.VulType
		if _, ok := m[key]; !ok {
			m[key] = v
		} else {
			return nil, fmt.Errorf("some uri %s and vul type %s has multiple vuls", v.URLPath, v.VulType)
		}
	}
	return m, nil
}
