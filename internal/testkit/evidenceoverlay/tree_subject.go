// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package evidenceoverlay

import "sort"

// ExactTreeSubject reads an explicitly bound immutable Git tree without
// asserting that any commit identifies it. Returned files have an empty Commit
// and the exact Tree; they must not be used as commit-bound evidence.
type ExactTreeSubject struct{ subject *historicalSubject }

func OpenExactTreeSubject(root, tree string) (*ExactTreeSubject, error) {
	s, err := openTreeSubject(root, tree)
	if err != nil {
		return nil, err
	}
	return &ExactTreeSubject{subject: s}, nil
}

func (s *ExactTreeSubject) Read(path string) (HistoricalFile, error) {
	return s.subject.read(path)
}

func (s *ExactTreeSubject) Paths() []string {
	paths := make([]string, 0, len(s.subject.entries))
	for path, entry := range s.subject.entries {
		if entry.Type != "tree" {
			paths = append(paths, path)
		}
	}
	sort.Strings(paths)
	return paths
}
