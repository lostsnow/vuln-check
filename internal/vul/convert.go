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
	case "无漏洞":
		return None
	case "命令执行":
		return CmdInjection
	case "弱加密":
		return "crypto-bad-ciphers"
	case "弱哈希":
		return "crypto-bad-mac"
	case "弱随机":
		return "crypto-weak-randomness"
	case "SQL注入":
		return "sql-injection"
	case "路径穿越":
		return "path-traversal"
	case "服务器端请求伪造":
		return "ssrf"
	case "XXE":
		return "xxe"
	case "反射型XSS":
		return "reflected-xss"
	case "LDAP注入":
		return "ldap-injection"
	case "XPATH注入":
		return "xpath-injection"
	case "JNI注入":
		return "dynamic-library-load"
	case "HQL注入":
		return "hql-injection"
	case "不安全的反序列化":
		return "unsafe-json-deserialize"
	case "任意文件上传":
		// unrestricted-file-upload
		return "FileWrite"
	case "不安全的重定向":
		return "unvalidated-redirect"
	case "Cookie未设置secure":
		return "cookie-flags-missing"
	case "信任边界":
		return "trust-boundary-violation"
	case "身份认证":
		return "身份认证"
	case "敏感信息泄露":
		return "手机号码泄漏"
	case "":
		return "empty"
	default:
		return "invalid"
	}
}

func parseExpectResult(result string) string {
	switch result {
	case "是":
		return ExpectYes
	case "否":
		return ExpectNo
	default:
		return ExpectUnknown
	}
}

func parseActualResult(result string) string {
	switch result {
	case "正常":
		return ActualOK
	case "漏报":
		return ActualMissing
	case "误报":
		return ActualWrong
	case "不支持":
		return ActualNoSupport
	default:
		return ActualNoConfirm
	}
}
