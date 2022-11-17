package cmd

import (
	"fmt"
	"os"
	"strings"

	"vuln-check/internal/vul"

	"github.com/litsea/logger"
	"github.com/spf13/cobra"
)

var (
	yamlToCheck string
	vulApp      string
	projectId   int64
	outDir      string
)

// ./vuln-check check --app benchmark --project-id 206
// ./vuln-check check --yaml ./data/vuls.yaml --out ./data --app benchmark --project-id 200
var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "Check all vulnerabilities by yaml",
	Run: func(cmd *cobra.Command, args []string) {
		prefix := "[check]"
		app, err := vul.ParseApp(vulApp)
		if err != nil {
			logger.Errorf("%s ParseApp failed: %s", prefix, err)
			return
		}

		if outDir[len(outDir)-1:] == "/" {
			outDir = outDir[:len(outDir)-1]
		}
		outFile := outDir + "/vuls-" + app + ".md"
		f, err := os.Create(outFile)
		if err != nil {
			logger.Error(fmt.Errorf("create/open out file %s failed: %w", outFile, err))
			return
		}
		defer func(f *os.File) {
			err := f.Close()
			if err != nil {
				logger.Error(fmt.Errorf("close out file %s failed: %w", outFile, err))
			}
		}(f)

		vulMap, err := vul.ParseVulYaml(yaml, app)
		if err != nil {
			logger.Errorf("%s ParseVulYaml failed: %s", prefix, err)
			return
		}
		logger.Infof("%s parse vul yaml successful: %d", prefix, len(vulMap))

		agent, err := vul.GetLatestAgent(projectId)
		if err != nil {
			logger.Errorf("%s GetLatestAgent failed: %s", prefix, err)
			return
		}
		logger.Infof("%s agent id: %d", prefix, agent.Id)

		vulTypeMap, err := vul.GetVulTypeMap()
		if err != nil {
			logger.Errorf("%s GetVulTypeMap failed: %s", prefix, err)
			return
		}
		logger.Infof("%s get vul type successful: %d", prefix, len(vulTypeMap))

		scanResultMap, err := vul.GetScanResults(agent.Id, vulTypeMap)
		if err != nil {
			logger.Errorf("%s GetScanResults failed: %s", prefix, err)
			return
		}
		logger.Infof("%s get scan result successful: %d", prefix, len(scanResultMap))

		checkResults, err := vul.Check(vulMap, scanResultMap)
		if err != nil {
			logger.Errorf("%s Check failed: %s", prefix, err)
			return
		}

		out := formatResult(checkResults)
		_, err = f.WriteString(out)
		if err != nil {
			logger.Errorf("%s write check result to %s failed: %s", prefix, outFile, err)
			return
		}
		logger.Infof("%s write check result to %s successful", prefix, outFile)
	},
}

func formatResult(vs []vul.CheckResult) string {
	sb := &strings.Builder{}
	sb.WriteString("# Vulnerability Scan Report\n\n")
	sb.WriteString("Expect Result:\n\n")
	sb.WriteString("* Yes: 有漏洞\n")
	sb.WriteString("* No: 无漏洞\n")
	sb.WriteString("* Unknown: 待确认\n\n")
	sb.WriteString("Actual Result:\n\n")
	sb.WriteString("* OK: 正常检出\n")
	sb.WriteString("* Missing: 漏报\n")
	sb.WriteString("* Wrong: 误报\n")
	sb.WriteString("* NoSupport: 不支持\n")
	sb.WriteString("* NoConfirm: 待确认\n\n")
	sb.WriteString("Expect Status:\n\n")
	sb.WriteString("* 😁: 检测正常\n")
	sb.WriteString("* 😰: 检测有误\n")
	sb.WriteString("* 😇: 未知\n\n")
	sb.WriteString("Check Status:\n\n")
	sb.WriteString("* ✅: 正常\n")
	sb.WriteString("* ❌: 异常\n")
	sb.WriteString("* ❓: 待确认\n\n")
	sb.WriteString("| Path | VulType | Expect | Actual | Description |\n")
	sb.WriteString("| ---- | ------- | ------ | ------ | ----------- |\n")

	wrongSb := &strings.Builder{}
	wrongSb.WriteString("## Extra Wrong\n\n")
	wrongSb.WriteString("| Path | VulType | Actual | Description |\n")
	wrongSb.WriteString("| ---- | ------- | ------ | ----------- |\n")

	for _, v := range vs {
		if !v.ExtraWrong {
			sb.WriteString("| ")
			sb.WriteString(v.UrlPath)
			sb.WriteString(" | ")
			sb.WriteString(v.VulType)
			sb.WriteString(" | ")
			if v.ActualResult == vul.ActualOK {
				sb.WriteString("😁")
			} else if v.ActualResult == vul.ActualNoConfirm {
				sb.WriteString("😇")
			} else {
				sb.WriteString("😰")
			}
			sb.WriteString(v.ExpectResult)
			sb.WriteString(" | ")
			if v.ActualResult == vul.ActualNoConfirm {
				sb.WriteString("❓")
			} else if v.ActualResult != v.OriginActualResult {
				sb.WriteString("❌")
			} else {
				sb.WriteString("✅")
			}
			sb.WriteString(v.ActualResult)
			sb.WriteString(" | ")
			sb.WriteString(v.Description)
			sb.WriteString(" |\n")
		} else {
			wrongSb.WriteString("| ")
			wrongSb.WriteString(v.UrlPath)
			wrongSb.WriteString(" | ")
			wrongSb.WriteString(v.VulType)
			wrongSb.WriteString(" | ")
			wrongSb.WriteString("😰")
			wrongSb.WriteString(v.ActualResult)
			wrongSb.WriteString(" | ")
			wrongSb.WriteString(v.Description)
			wrongSb.WriteString(" |\n")
		}
	}
	sb.WriteString("\n")
	wrongSb.WriteString("\n")
	sb.WriteString(wrongSb.String())

	return sb.String()
}

func init() {
	checkCmd.Flags().StringVar(&yamlToCheck, "yaml", "./data/vuls.yaml", "yaml file path to check vulnerability")
	checkCmd.Flags().StringVar(&vulApp, "app", "", "app to check vulnerability (webgoat, benchmark, openrasp)")
	checkCmd.Flags().Int64Var(&projectId, "project-id", 0, "project id to check vulnerability")
	checkCmd.Flags().StringVar(&outDir, "out", "./data", "output file dir to vulnerability check result")
	rootCmd.AddCommand(checkCmd)
}
