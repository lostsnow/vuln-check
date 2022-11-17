package vul

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type CheckResult struct {
	UrlPath            string
	VulType            string
	ExpectResult       string
	ActualResult       string
	OriginActualResult string
	Description        string
	ExtraWrong         bool
}

func Check(vulMap map[string]Vul, scanResultMap map[string]ScanResult) ([]CheckResult, error) {
	var results []CheckResult

	for k, v := range vulMap {
		var r string
		_, exists := scanResultMap[k]
		if v.ExpectResult == ExpectYes {
			if exists {
				r = ActualOK
			} else {
				if v.ActualResult == ActualNoSupport {
					r = ActualNoSupport
				} else {
					r = ActualMissing
				}
			}
		} else if v.ExpectResult == ExpectNo {
			if exists {
				r = ActualWrong
			} else {
				r = ActualOK
			}
		} else if v.ExpectResult == ExpectUnknown {
			r = ActualNoConfirm
		}

		results = append(results, CheckResult{
			UrlPath:            v.URLPath,
			VulType:            v.VulType,
			ExpectResult:       v.ExpectResult,
			ActualResult:       r,
			OriginActualResult: v.ActualResult,
			Description:        v.Description,
		})
	}

	for k, v := range scanResultMap {
		if _, ok := vulMap[k]; !ok {
			results = append(results, CheckResult{
				UrlPath:      v.URLPath,
				VulType:      v.VulType,
				ExpectResult: ExpectNo,
				ActualResult: ActualWrong,
				ExtraWrong:   true,
			})
		}
	}

	sort.Slice(results, func(i, j int) bool {
		if results[i].UrlPath != results[j].UrlPath {
			return results[i].UrlPath < results[j].UrlPath
		}
		return results[i].VulType < results[j].VulType
	})

	return results, nil
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
		path := NormalizeUrlPath(v.URLPath)
		v.URLPath = path
		key := path + "::" + v.VulType
		if _, ok := m[key]; !ok {
			m[key] = v
		} else {
			return nil, fmt.Errorf("some uri %s and vul type %s has multiple vulnerabilities in yaml %s",
				v.URLPath, v.VulType, yamlPath)
		}
	}
	return m, nil
}
