package vul

import (
	"encoding/csv"
	"fmt"
	"os"
	"strings"
)

func Convert(csvPath, yamlPath string) (int, error) {
	f, err := os.Open(csvPath)
	if err != nil {
		return 0, fmt.Errorf("open csv %s failed: %w", csvPath, err)
	}
	defer func(f *os.File) {
		err := f.Close()
		if err != nil {
			fmt.Printf("csv %s close failed: %s\n", csvPath, err)
		}
	}(f)

	r := csv.NewReader(f)
	records, err := r.ReadAll()
	if err != nil {
		return 0, fmt.Errorf("read csv %s failed: %w", csvPath, err)
	}

	vuls := make([]Vul, 0, len(records))
	for idx, rd := range records {
		if idx == 0 {
			continue
		}
		if len(rd) != 7 {
			return 0, fmt.Errorf("invalid record: %v", rd)
		}

		appVersion, err := parseApp(rd[1])
		if err != nil {
			return 0, err
		}
		vulType := parseVulType(rd[3])
		if vulType == "invalid" {
			return 0, fmt.Errorf("invalid vul type: %v", rd)
		}

		vul := Vul{
			App:          appVersion[0],
			AppVersion:   appVersion[1],
			URLPath:      strings.TrimSpace(rd[2]),
			VulType:      vulType,
			ExpectResult: parseExpectResult(rd[4]),
			ActualResult: parseActualResult(rd[5]),
			Description:  rd[6],
		}
		vuls = append(vuls, vul)
	}

	return len(vuls), toYaml(vuls, yamlPath)
}

func toYaml(vuls []Vul, yamlPath string) error {
	if len(vuls) == 0 {
		return fmt.Errorf("empty vuls")
	}

	f, err := os.Create(yamlPath)
	if err != nil {
		return fmt.Errorf("create/open yaml file %s failed: %w", yamlPath, err)
	}

	for _, vul := range vuls {
		p := []byte(`- app: "` + vul.App + "\"\n" +
			`  appVersion: "` + vul.AppVersion + "\"\n" +
			`  urlPath: "` + vul.URLPath + "\"\n" +
			`  vulType: "` + vul.VulType + "\"\n" +
			`  expectResult: "` + vul.ExpectResult + "\"\n" +
			`  actualResult: "` + vul.ActualResult + "\"\n" +
			`  description: "` + vul.Description + "\"\n")
		_, err2 := f.Write(p)
		if err2 != nil {
			return fmt.Errorf("write %v to yaml file %s failed: %w", vul, yamlPath, err)
		}
	}

	return nil
}

func parseApp(appWithVersion string) ([]string, error) {
	pairs := strings.Split(appWithVersion, " ")
	if len(pairs) != 2 {
		return nil, fmt.Errorf("invalid app %s", appWithVersion)
	}
	return pairs, nil
}

func parseVulType(v string) string {
	switch v {
	case "?????????":
		return None
	case "????????????":
		return CmdInjection
	case "?????????":
		return "crypto-bad-ciphers"
	case "?????????":
		return "crypto-bad-mac"
	case "?????????":
		return "crypto-weak-randomness"
	case "SQL??????":
		return "sql-injection"
	case "????????????":
		return "path-traversal"
	case "????????????????????????":
		return "ssrf"
	case "XXE":
		return "xxe"
	case "?????????XSS":
		return "reflected-xss"
	case "LDAP??????":
		return "ldap-injection"
	case "XPATH??????":
		return "xpath-injection"
	case "JNI??????":
		return "dynamic-library-load"
	case "JNDI??????":
		return "JNDI??????"
	case "HQL??????":
		return "hql-injection"
	case "????????????????????????":
		return "unsafe-json-deserialize"
	case "??????????????????":
		// unrestricted-file-upload
		return "FileWrite"
	case "?????????????????????":
		return "unvalidated-redirect"
	case "Cookie?????????secure":
		return "cookie-flags-missing"
	case "????????????":
		return "trust-boundary-violation"
	case "????????????":
		return "????????????"
	case "CSRF":
		return "csrf"
	case "?????????":
		return "?????????"
	case "??????????????????":
		return "??????????????????"
	case "":
		return "empty"
	default:
		return "invalid"
	}
}

func parseExpectResult(result string) string {
	switch result {
	case "???":
		return ExpectYes
	case "???":
		return ExpectNo
	default:
		return ExpectUnknown
	}
}

func parseActualResult(result string) string {
	switch result {
	case "??????":
		return ActualOK
	case "??????":
		return ActualMissing
	case "??????":
		return ActualWrong
	case "?????????":
		return ActualNoSupport
	case "??????":
		return ActualIndirect
	default:
		return ActualNoConfirm
	}
}
