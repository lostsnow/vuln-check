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

// ./vuln-check vulConvert --csv ./data/vuls.csv --yaml ./data/vuls.yaml
var vulConvertCmd = &cobra.Command{
	Use:   "vulConvert",
	Short: "Convert all vuls to yaml",
	Run: func(cmd *cobra.Command, args []string) {
		total, err := vul.Convert(csv, yaml)
		if err != nil {
			logger.Errorf("vuls convert failed %w", err)
			return
		}
		logger.Infof("vuls convert successfully: %d", total)
	},
}

func init() {
	vulConvertCmd.Flags().StringVar(&csv, "csv", "", "path of the csv file to be converted")
	vulConvertCmd.Flags().StringVar(&yaml, "yaml", "", "file path to convert to yaml")
	rootCmd.AddCommand(vulConvertCmd)
}
