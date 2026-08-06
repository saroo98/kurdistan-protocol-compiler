// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package migrations

import (
	"reflect"
	"testing"

	"cloud.google.com/go/spanner/spansql"
)

func TestManifestIsChecksumBoundAndComplete(t *testing.T) {
	migrations, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"Approvals", "AuditAnchors", "AuditEvents", "AuthorityHead", "AuthoritySources", "Ceremonies",
		"EmergencyAuthorities", "EmergencyRestrictions", "IdempotencyReceipts", "KeyVersions",
		"Operations", "OutboxEvents", "Profiles", "Publications", "Relays", "SchemaMigrations", "TokenReplay",
	}
	if got := RequiredTables(migrations); !reflect.DeepEqual(got, want) {
		t.Fatalf("tables=%v", got)
	}
	for _, migration := range migrations {
		for _, statement := range migration.Statements {
			if _, err := spansql.ParseDDL(migration.File, statement+";"); err != nil {
				t.Fatalf("parse %s: %v", migration.File, err)
			}
		}
	}
}

func TestDestructiveMigrationIsRejected(t *testing.T) {
	if _, err := splitStatements("DROP TABLE AuthorityHead;"); err == nil {
		t.Fatal("destructive migration accepted")
	}
}
