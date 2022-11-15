package cmd

import (
	"fmt"
	"strings"

	"vuln-check/internal/vul"

	"github.com/litsea/logger"
	"github.com/spf13/cobra"
)

var (
	yamlToCheck string
	vulApp      string
	projectId   int64
)

// ./vuln-check check --yaml ./data/vuls.yaml
var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "Check all vuls by yaml",
	Run: func(cmd *cobra.Command, args []string) {
		prefix := "[check]"
		app, err := vul.ParseApp(vulApp)
		if err != nil {
			logger.Errorf("%s ParseApp failed: %s", prefix, err)
			return
		}

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

		checkResult, err := vul.Check(vulMap, scanResultMap)
		if err != nil {
			logger.Errorf("%s Check failed: %s", prefix, err)
			return
		}

		builder := &strings.Builder{}
		fmt.Println("==========================================================")
		formatVul(builder, app, vul.ScanOK, checkResult.MatchedVuls)
		formatVul(builder, app, vul.ScanMissing, checkResult.MissingResult)
		formatScanResult(builder, app, vul.ScanWrong, checkResult.WrongScanResults)
		formatVul(builder, app, vul.ScanNone, checkResult.NoneVuls)
		formatVul(builder, app, vul.ScanNoSupport, checkResult.NoSupportVuls)
		fmt.Println(builder.String())
		fmt.Println("==========================================================")

		logger.Infof("%s successfully", prefix)
	},
}

func formatVul(builder *strings.Builder, app, t string, vs []vul.Vul) {
	builder.WriteString("## " + t + "\n\n")
	for _, v := range vs {
		path := vul.NormalizeUrlPathForBenchmark(app, v.VulType, v.URLPath)
		builder.WriteString("* [" + t + "] " + path + ": " + v.VulType + "\n")
	}
	builder.WriteString("\n")
}

func formatScanResult(builder *strings.Builder, app, t string, vs []vul.ScanResult) {
	builder.WriteString("## " + t + "\n\n")
	for _, v := range vs {
		path := vul.NormalizeUrlPathForBenchmark(app, v.VulType, v.URLPath)
		builder.WriteString("* [" + t + "] " + path + ": " + v.VulType + "\n")
	}
	builder.WriteString("\n")
}

func init() {
	checkCmd.Flags().StringVar(&yamlToCheck, "yaml", "./data/vuls.yaml", "yaml file path to check vul")
	checkCmd.Flags().StringVar(&vulApp, "app", "", "app to check vul (webgoat, benchmark, openrasp)")
	checkCmd.Flags().Int64Var(&projectId, "project-id", 0, "project id to check vul")
	rootCmd.AddCommand(checkCmd)
}
