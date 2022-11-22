package vul

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"vuln-check/internal/datasource/header_vulnerability"
	"vuln-check/internal/db"

	"github.com/litsea/logger"
	"gopkg.in/yaml.v3"
)

var (
	indirectVul = map[string]struct{}{
		"sun.security.rsa.MGF1.<init>(MGF1.java:47)": {},
	}
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
	results := make([]CheckResult, 0)

	missingNormalVulIds := make([]string, 0)
	missingNormalVuls := make([]CheckResult, 0)

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

		if r == ActualMissing && NeedCheckUriRelation(v.VulType) {
			missingNormalVuls = append(missingNormalVuls, CheckResult{
				UrlPath:            v.URLPath,
				VulType:            v.VulType,
				ExpectResult:       v.ExpectResult,
				ActualResult:       r,
				OriginActualResult: v.ActualResult,
				Description:        v.Description,
			})
		} else {
			results = append(results, CheckResult{
				UrlPath:            v.URLPath,
				VulType:            v.VulType,
				ExpectResult:       v.ExpectResult,
				ActualResult:       r,
				OriginActualResult: v.ActualResult,
				Description:        v.Description,
			})
		}
	}

	for k, v := range scanResultMap {
		if _, ok := vulMap[k]; !ok {
			if NeedCheckUriRelation(v.VulType) {
				missingNormalVulIds = append(missingNormalVulIds, strconv.FormatInt(v.Id, 10))
			}
			results = append(results, CheckResult{
				UrlPath:      v.URLPath,
				VulType:      v.VulType,
				ExpectResult: ExpectNo,
				ActualResult: ActualWrong,
				ExtraWrong:   true,
			})
		}
	}

	if len(missingNormalVulIds) > 0 {
		filters := make(map[string]interface{})
		filters["vul_id"] = strings.Join(missingNormalVulIds, ",")
		query := &db.MySQLQuery{
			Where:  "vul_id IN (@vul_id)",
			Args:   filters,
			Fields: []string{"id", "url"},
		}
		hVuls, err := header_vulnerability.GetHeaderVulnerabilities(query)
		if err != nil {
			logger.Error(err)
		} else {
			hVulMap := make(map[string]struct{})
			for _, hVul := range hVuls {
				path := NormalizeUrlPath(hVul.Url)
				hVulMap[path] = struct{}{}
			}
			for _, missingNormalVul := range missingNormalVuls {
				if _, ok := hVulMap[missingNormalVul.UrlPath]; ok {
					missingNormalVul.ActualResult = ActualOK
				}
				results = append(results, missingNormalVul)
			}
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
