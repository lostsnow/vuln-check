package vul

import (
	"fmt"

	"vuln-check/internal/datasource/agent"
	"vuln-check/internal/datasource/strategy"
	"vuln-check/internal/datasource/vulnerability"
	"vuln-check/internal/db"

	"github.com/litsea/logger"
)

const (
	ScanOK        = "OK"
	ScanMissing   = "Missing"
	ScanWrong     = "Wrong"
	ScanNone      = "None"
	ScanNoSupport = "NoSupport"
	ScanNoConfirm = "NoConfirm"
)

type ScanResult struct {
	Id      int64
	URLPath string
	VulType string
}

type MissingRequest struct {
	Id      int64
	URLPath string
}

func GetLatestAgent(projectId int64) (*agent.Agent, error) {
	filters := make(map[string]interface{})
	filters["bind_project_id"] = projectId
	query := &db.MySQLQuery{
		Where:  "bind_project_id = @bind_project_id",
		Args:   filters,
		Fields: []string{"id", "bind_project_id"},
		Limit:  1,
		Order:  "id DESC",
	}

	v, err := agent.GetAgent(query)
	if err != nil {
		return nil, fmt.Errorf("get latest agent for project %d failed: %w", projectId, err)
	}

	return v, nil
}

func GetVulTypeMap() (map[int64]string, error) {
	query := &db.MySQLQuery{
		Where:  "system_type = 1",
		Fields: []string{"id", "vul_type"},
	}

	vs, err := strategy.GetStrategies(query)
	if err != nil {
		return nil, err
	}

	m := make(map[int64]string, len(vs))
	for _, v := range vs {
		m[v.Id] = v.VulType
	}
	return m, nil
}

func GetScanResults(agentId int64, vulTypeMap map[int64]string) (map[string]ScanResult, error) {
	filters := make(map[string]interface{})
	filters["agent_id"] = agentId
	query := &db.MySQLQuery{
		Where:  "agent_id = @agent_id",
		Args:   filters,
		Fields: []string{"id", "uri", "strategy_id"},
	}

	vs, err := vulnerability.GetVulnerabilities(query)
	if err != nil {
		return nil, err
	}

	m := make(map[string]ScanResult, len(vs))
	for _, v := range vs {
		vulType, ok := vulTypeMap[v.StrategyId]
		if !ok {
			vulType = "unknown"
		}
		r := ScanResult{
			Id:      v.Id,
			URLPath: v.Uri,
			VulType: vulType,
		}

		key := v.Uri + "::" + vulType
		if _, ok = m[key]; !ok {
			m[key] = r
		} else {
			logger.Warnf("some uri %s and vul type %s has multiple vulnerabilities", v.Uri, vulType)
		}
	}

	return m, nil
}

func GetMissingRequest() ([]MissingRequest, error) {
	return nil, nil
}
