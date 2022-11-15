package strategy

import (
	"fmt"

	"vuln-check/internal/db"
)

type Strategy struct {
	Id      int64  `gorm:"primaryKey"`
	VulType string `json:"vul_type"`
}

func (m *Strategy) TableName() string {
	return "iast_strategy"
}

func GetStrategies(query *db.MySQLQuery) ([]Strategy, error) {
	var v []Strategy
	err := query.GetMany((&Strategy{}).TableName(), &v)
	if err != nil {
		return nil, fmt.Errorf("get strategies failed: %w", err)
	}
	return v, nil
}
