package agent

import (
	"fmt"

	"vuln-check/internal/db"
)

type Agent struct {
	Id            int64 `gorm:"primaryKey"`
	BindProjectId int64 `json:"bind_project_id"`
}

func (m *Agent) TableName() string {
	return "iast_agent"
}

func GetAgents(query *db.MySQLQuery) ([]Agent, error) {
	var v []Agent
	err := query.GetMany((&Agent{}).TableName(), &v)
	if err != nil {
		return nil, fmt.Errorf("get agents failed: %w", err)
	}
	return v, nil
}

func GetAgent(query *db.MySQLQuery) (*Agent, error) {
	var v Agent
	err := query.GetOne((&Agent{}).TableName(), &v)
	if err != nil {
		return nil, fmt.Errorf("get agents failed: %w", err)
	}
	return &v, nil
}
