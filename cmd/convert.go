package cmd

import (
	"vuln-check/internal/vul"

	"github.com/litsea/logger"
	"github.com/spf13/cobra"
)

var (
	csv  string
	yaml string
)

// ./vuln-check vulConvert
// ./vuln-check vulConvert --csv ./data/vuls.csv --yaml ./data/vuls.yaml
var vulConvertCmd = &cobra.Command{
	Use:   "vulConvert",
	Short: "Convert all vulnerabilities to yaml",
	Run: func(cmd *cobra.Command, args []string) {
		prefix := "[convert]"
		total, err := vul.Convert(csv, yaml)
		if err != nil {
			logger.Errorf("%s failed %w", prefix, err)
			return
		}
		logger.Infof("%s successfully: %d", prefix, total)
	},
}

func init() {
	vulConvertCmd.Flags().StringVar(&csv, "csv", "./data/vuls.csv", "path of the csv file to be converted")
	vulConvertCmd.Flags().StringVar(&yaml, "yaml", "./data/vuls.yaml", "file path to convert to yaml")
	rootCmd.AddCommand(vulConvertCmd)
}
