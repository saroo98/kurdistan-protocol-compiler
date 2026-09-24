// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package evidenceoverlay

import (
	"bytes"
	"compress/zlib"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func treeSubjectGit(t *testing.T, root, input string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", root}, args...)...)
	for _, item := range os.Environ() {
		key, _, _ := strings.Cut(item, "=")
		if !strings.HasPrefix(strings.ToUpper(key), "GIT_") {
			cmd.Env = append(cmd.Env, item)
		}
	}
	cmd.Env = append(cmd.Env, "GIT_OPTIONAL_LOCKS=0", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull)
	cmd.Stdin = strings.NewReader(input)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("test-local git %v: %v: %s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func treeSubjectFixture(t *testing.T) (root, commit, tree, blob string) {
	t.Helper()
	root = t.TempDir()
	treeSubjectGit(t, root, "", "init", "--object-format=sha1")
	treeSubjectGit(t, root, "", "config", "user.name", "Fixture")
	treeSubjectGit(t, root, "", "config", "user.email", "fixture@example.invalid")
	base := treeSubjectGit(t, root, "", "mktree")
	commit = treeSubjectGit(t, root, "baseline\n", "commit-tree", base)
	treeSubjectGit(t, root, "", "update-ref", "HEAD", commit)
	blob = treeSubjectGit(t, root, "exact\r\nbytes\x00\n", "hash-object", "-w", "--stdin")
	nested := treeSubjectGit(t, root, "100755 blob "+blob+"\trun\n", "mktree")
	tree = treeSubjectGit(t, root, "100644 blob "+blob+"\ta.txt\n040000 tree "+nested+"\tdir\n", "mktree")
	// Neither HEAD nor the absent test-local index identifies this candidate.
	writeOverlayForTest(t, root, "a.txt", "moving checkout must not be read")
	writeOverlayForTest(t, root, "dir/shadow", "not an immutable tree entry")
	return
}

func TestExactTreeSubjectUncommittedIdentityAndDefensiveCopies(t *testing.T) {
	root, commit, tree, blob := treeSubjectFixture(t)
	s, err := OpenExactTreeSubject(root, tree)
	if err != nil {
		t.Fatal(err)
	}
	for path, mode := range map[string]string{"a.txt": "100644", "dir/run": "100755"} {
		f, err := s.Read(path)
		want := []byte("exact\r\nbytes\x00\n")
		if err != nil || f.Commit != "" || f.Tree != tree || f.Path != path || f.Mode != mode ||
			f.Type != "blob" || f.ObjectID != blob || f.Length != 14 || !bytes.Equal(f.Content, want) ||
			f.SHA256 != fmt.Sprintf("%x", sha256.Sum256(want)) {
			t.Fatalf("tree-only identity or literal bytes lost: %+v, %v", f, err)
		}
		f.Content[0] = '!'
		again, err := s.Read(path)
		if err != nil || !bytes.Equal(again.Content, want) {
			t.Fatalf("caller content mutation escaped: %+v, %v", again, err)
		}
	}
	paths := s.Paths()
	if !reflect.DeepEqual(paths, []string{"a.txt", "dir/run"}) {
		t.Fatalf("non-file or unsorted inventory: %v", paths)
	}
	paths[0] = "mutated"
	if s.Paths()[0] != "a.txt" {
		t.Fatal("caller inventory mutation escaped")
	}
	if _, err := OpenExactSubject(root, commit, tree); err == nil {
		t.Fatal("tree-only support weakened commit/tree binding")
	}
	if treeSubjectGit(t, root, "", "rev-parse", "HEAD") != commit {
		t.Fatal("reader changed HEAD")
	}
	if _, err := os.Stat(filepath.Join(root, ".git", "index")); !os.IsNotExist(err) {
		t.Fatalf("reader created an index: %v", err)
	}
}

func TestExactTreeSubjectRejectsWrongMissingAndSymbolicTrees(t *testing.T) {
	root, commit, _, blob := treeSubjectFixture(t)
	for _, tree := range []string{"", "HEAD^{tree}", strings.Repeat("f", 40), strings.ToUpper(blob), blob, commit} {
		if _, err := OpenExactTreeSubject(root, tree); err == nil {
			t.Fatalf("nonexact or wrong-type tree accepted: %q", tree)
		}
	}
	_, _, tree, _ := treeSubjectFixture(t)
	if _, err := OpenExactTreeSubject(t.TempDir(), tree); err == nil {
		t.Fatal("standalone filesystem used as tree fallback")
	}
	if _, err := OpenExactTreeSubject(filepath.Join(root, "dir"), tree); err == nil {
		t.Fatal("non-root path accepted")
	}
}

func TestExactTreeSubjectIgnoresInheritedGitSubjectOverrides(t *testing.T) {
	root, _, tree, blob := treeSubjectFixture(t)
	other, _, _, _ := treeSubjectFixture(t)
	t.Setenv("GIT_DIR", filepath.Join(other, ".git"))
	t.Setenv("GIT_WORK_TREE", other)
	t.Setenv("GIT_INDEX_FILE", filepath.Join(other, "nonexistent-index"))
	t.Setenv("GIT_OBJECT_DIRECTORY", filepath.Join(other, "missing-objects"))
	s, err := OpenExactTreeSubject(root, tree)
	if err != nil {
		t.Fatal(err)
	}
	f, err := s.Read("a.txt")
	if err != nil || f.Tree != tree || f.ObjectID != blob || string(f.Content) != "exact\r\nbytes\x00\n" {
		t.Fatalf("inherited Git state redirected exact subject: %+v, %v", f, err)
	}
}

func TestExactTreeSubjectRejectsPathsModesAndTypes(t *testing.T) {
	root, commit, tree, blob := treeSubjectFixture(t)
	s, err := OpenExactTreeSubject(root, tree)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"", "../a.txt", "/a.txt", "a\\b", "a:b", ".git/config", "a\x00b", "dir", "absent"} {
		if _, err := s.Read(path); err == nil {
			t.Fatalf("unsupported path/type accepted: %q", path)
		}
	}
	for name, row := range map[string]string{
		"symlink": "120000 blob " + blob + "\ta.txt\n",
		"gitlink": "160000 commit " + commit + "\ta.txt\n",
		"private": "100644 blob " + blob + "\t.codex-private\n",
		"dotgit":  "100644 blob " + blob + "\t.git\n",
		"parent":  "100644 blob " + blob + "\t..\n",
	} {
		t.Run(name, func(t *testing.T) {
			badTree := treeSubjectGit(t, root, row, "mktree")
			bad, err := OpenExactTreeSubject(root, badTree)
			if err == nil {
				if name != "symlink" && name != "gitlink" {
					t.Fatal("unsafe path admitted into tree inventory")
				}
				_, err = bad.Read("a.txt")
			}
			if err == nil {
				t.Fatal("unsupported tree entry admitted")
			}
		})
	}
}

func TestExactTreeSubjectRejectsMissingAndCorruptObjectsWithoutFallback(t *testing.T) {
	for _, kind := range []string{"tree", "blob"} {
		for _, mutation := range []string{"missing", "corrupt"} {
			t.Run(kind+"/"+mutation, func(t *testing.T) {
				root, _, tree, blob := treeSubjectFixture(t)
				oid := tree
				var subject *ExactTreeSubject
				var err error
				if kind == "blob" {
					oid = blob
					subject, err = OpenExactTreeSubject(root, tree)
					if err != nil {
						t.Fatal(err)
					}
				}
				path := filepath.Join(root, ".git", "objects", oid[:2], oid[2:])
				if err := os.Chmod(path, 0o600); err != nil {
					t.Fatal(err)
				}
				if mutation == "missing" {
					err = os.Remove(path)
				} else {
					var encoded bytes.Buffer
					w := zlib.NewWriter(&encoded)
					_, writeErr := fmt.Fprintf(w, "%s 14\x00wrong\r\nbytes!\n", kind)
					if writeErr != nil {
						t.Fatal(writeErr)
					}
					if err := w.Close(); err != nil {
						t.Fatal(err)
					}
					err = os.WriteFile(path, encoded.Bytes(), 0o600)
				}
				if err != nil {
					t.Fatal(err)
				}
				if kind == "tree" {
					_, err = OpenExactTreeSubject(root, tree)
				} else {
					_, err = subject.Read("a.txt")
				}
				if err == nil {
					t.Fatal("missing/corrupt object replaced by another subject")
				}
			})
		}
	}
}
