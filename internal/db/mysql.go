package db

import (
	"fmt"

	"github.com/spf13/viper"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var (
	MySQL *gorm.DB
)

type MySQLQuery struct {
	Where  string
	Args   map[string]interface{}
	Fields []string
	Order  string
	Limit  int
	Offset int
}

func InitMySQL() error {
	dsn := viper.GetString("mysql.dsn")

	db, err := NewMySQL(dsn)
	if err != nil {
		return err
	}

	// connection pool
	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("failed to get sql db: %w", err)
	}
	// need same open connections and idle connections
	// @see: https://github.com/go-sql-driver/mysql/issues/991#issuecomment-526035935
	sqlDB.SetMaxIdleConns(viper.GetInt("mysql.max-open-conn"))
	sqlDB.SetMaxOpenConns(viper.GetInt("mysql.max-open-conn"))
	sqlDB.SetConnMaxLifetime(viper.GetDuration("mysql.conn-max-lifetime"))

	MySQL = db
	return nil
}

func NewMySQL(dsn string) (*gorm.DB, error) {
	return gorm.Open(mysql.Open(dsn), &gorm.Config{
		Logger: logger.Discard,
	})
}

func (query *MySQLQuery) GetOne(table string, v interface{}) error {
	q := MySQL.Table(table)
	if query.Args != nil {
		q = q.Where(query.Where, query.Args)
	} else {
		q = q.Where(query.Where)
	}

	if len(query.Fields) > 0 {
		q = q.Select(query.Fields)
	}

	if query.Order != "" {
		q = q.Order(query.Order)
	}

	return q.Take(v).Error
}

func (query *MySQLQuery) GetMany(table string, v interface{}) error {
	q := MySQL.Table(table)
	if query.Args != nil {
		q = q.Where(query.Where, query.Args)
	} else {
		q = q.Where(query.Where)
	}

	if len(query.Fields) > 0 {
		q = q.Select(query.Fields)
	}

	if query.Limit > 0 {
		q = q.Limit(query.Limit).Offset(query.Offset)
		if query.Order == "" {
			q = q.Order("id")
		}
	}

	if query.Order != "" {
		q = q.Order(query.Order)
	}

	return q.Find(v).Error
}
