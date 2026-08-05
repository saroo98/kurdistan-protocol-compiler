// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package migrations

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

//go:embed manifest.json *.sql
var files embed.FS

var ErrInvalidManifest = errors.New("migrations: invalid manifest")

type Entry struct {
	Version uint64 `json:"version"`
	Name    string `json:"name"`
	File    string `json:"file"`
	SHA256  string `json:"sha256"`
}

type Manifest struct {
	Schema     string  `json:"schema"`
	Migrations []Entry `json:"migrations"`
}

type Migration struct {
	Entry
	Statements []string
}

var (
	nameRE   = regexp.MustCompile(`^[a-z][a-z0-9_-]{1,63}$`)
	fileRE   = regexp.MustCompile(`^[0-9]{3}_[a-z][a-z0-9_-]{1,63}\.sql$`)
	digestRE = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

func Load() ([]Migration, error) {
	raw, err := files.ReadFile("manifest.json")
	if err != nil || !uniqueObjectKeys(raw) {
		return nil, ErrInvalidManifest
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil || manifest.Schema != "phase16-spanner-migrations-v1" || len(manifest.Migrations) == 0 || len(manifest.Migrations) > 128 {
		return nil, ErrInvalidManifest
	}
	result := make([]Migration, 0, len(manifest.Migrations))
	seen := make(map[string]struct{}, len(manifest.Migrations))
	for index, entry := range manifest.Migrations {
		if entry.Version != uint64(index+1) || !nameRE.MatchString(entry.Name) || !fileRE.MatchString(entry.File) || !digestRE.MatchString(entry.SHA256) {
			return nil, ErrInvalidManifest
		}
		if _, duplicate := seen[entry.File]; duplicate {
			return nil, ErrInvalidManifest
		}
		seen[entry.File] = struct{}{}
		sql, err := files.ReadFile(entry.File)
		if err != nil {
			return nil, ErrInvalidManifest
		}
		digest := sha256.Sum256(sql)
		if hex.EncodeToString(digest[:]) != entry.SHA256 {
			return nil, fmt.Errorf("%w: checksum", ErrInvalidManifest)
		}
		statements, err := splitStatements(string(sql))
		if err != nil {
			return nil, err
		}
		result = append(result, Migration{Entry: entry, Statements: statements})
	}
	return result, nil
}

func splitStatements(sql string) ([]string, error) {
	upper := strings.ToUpper(sql)
	for _, forbidden := range []string{"DROP TABLE", "DROP COLUMN", "TRUNCATE", "DELETE FROM", "REPLACE INTO"} {
		if strings.Contains(upper, forbidden) {
			return nil, ErrInvalidManifest
		}
	}
	var statements []string
	for _, candidate := range strings.Split(sql, ";") {
		lines := strings.Split(candidate, "\n")
		kept := lines[:0]
		for _, line := range lines {
			if !strings.HasPrefix(strings.TrimSpace(line), "--") {
				kept = append(kept, line)
			}
		}
		candidate = strings.TrimSpace(strings.Join(kept, "\n"))
		if candidate != "" {
			statements = append(statements, candidate)
		}
	}
	if len(statements) == 0 || len(statements) > 128 {
		return nil, ErrInvalidManifest
	}
	return statements, nil
}

func RequiredTables(migrations []Migration) []string {
	var tables []string
	for _, migration := range migrations {
		for _, statement := range migration.Statements {
			fields := strings.Fields(statement)
			if len(fields) >= 3 && strings.EqualFold(fields[0], "CREATE") && strings.EqualFold(fields[1], "TABLE") {
				tables = append(tables, strings.Trim(fields[2], "`"))
			}
		}
	}
	sort.Strings(tables)
	return tables
}

func uniqueObjectKeys(raw []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return false
	}
	seen := map[string]struct{}{}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return false
		}
		key, ok := token.(string)
		if !ok {
			return false
		}
		if _, duplicate := seen[key]; duplicate {
			return false
		}
		seen[key] = struct{}{}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return false
		}
	}
	_, err = decoder.Token()
	return err == nil
}
