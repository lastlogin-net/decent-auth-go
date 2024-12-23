package decentauth

import (
	"database/sql"
	"errors"
	"fmt"
	"sync"

	_ "github.com/mattn/go-sqlite3"
)

type KvStore interface {
	Get(key string) (value []byte, err error)
	Set(key string, value []byte) (err error)
	Delete(key string) (err error)
	List(prefix string) (keys []string, err error)
}

type MemoryKvStore struct {
	data map[string][]byte
	mut  *sync.Mutex
}

func NewMemoryKvStore() *MemoryKvStore {
	return &MemoryKvStore{
		data: make(map[string][]byte),
		mut:  &sync.Mutex{},
	}
}

func (s *MemoryKvStore) Get(key string) (value []byte, err error) {
	s.mut.Lock()
	defer s.mut.Unlock()

	value, exists := s.data[key]
	if !exists {
		err = errors.New("Not found")
		return
	}

	return
}
func (s *MemoryKvStore) Set(key string, value []byte) (err error) {
	s.mut.Lock()
	defer s.mut.Unlock()

	s.data[key] = value

	return nil
}
func (s *MemoryKvStore) Delete(key string) (err error) {
	s.mut.Lock()
	defer s.mut.Unlock()

	delete(s.data, key)

	return nil
}

type kvStore struct {
	db        *sql.DB
	tableName string
}

type SqliteKvOptions struct {
	Db        *sql.DB
	TableName string
}

func NewSqliteKvStore(opt ...*SqliteKvOptions) (store *kvStore, err error) {

	var db *sql.DB
	tableName := "kv"

	if len(opt) > 0 {
		if opt[0].Db != nil {
			db = opt[0].Db
		}

		if opt[0].TableName != "" {
			tableName = opt[0].TableName
		}
	}

	if db == nil {
		db, err = sql.Open("sqlite3", "./db.sqlite")
		if err != nil {
			return nil, err
		}
	}

	store = &kvStore{
		db:        db,
		tableName: tableName,
	}

	stmt := fmt.Sprintf(`
        CREATE TABLE IF NOT EXISTS %s(
                key TEXT NOT NULL PRIMARY KEY,
                value BLOB NOT NULL
        );
        `, tableName)
	_, err = db.Exec(stmt)
	if err != nil {
		return
	}

	return
}

func (s *kvStore) Set(key string, value []byte) error {

	stmt := fmt.Sprintf(`
        INSERT OR REPLACE INTO %s(key, value) VALUES(?, ?);
        `, s.tableName)
	_, err := s.db.Exec(stmt, key, value)
	if err != nil {
		return err
	}

	return nil
}

func (s *kvStore) Get(key string) ([]byte, error) {

	var value []byte

	stmt := fmt.Sprintf(`
        SELECT value FROM %s WHERE key=?;
        `, s.tableName)
	err := s.db.QueryRow(stmt, key).Scan(&value)
	if err != nil {
		return nil, err
	}

	return value, nil
}

func (s *kvStore) Delete(key string) error {

	stmt := fmt.Sprintf(`
        DELETE FROM %s WHERE key=?;
        `, s.tableName)
	_, err := s.db.Exec(stmt, key)
	if err != nil {
		return err
	}

	return nil
}

func (s *kvStore) List(prefix string) ([]string, error) {

	var keys []string

	stmt := fmt.Sprintf(`
        SELECT key FROM %s WHERE key GLOB ? || '*'
        `, s.tableName)
	rows, err := s.db.Query(stmt, prefix)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var key string
		err = rows.Scan(&key)
		if err != nil {
			return nil, err
		}

		keys = append(keys, key)
	}

	return keys, nil
}
