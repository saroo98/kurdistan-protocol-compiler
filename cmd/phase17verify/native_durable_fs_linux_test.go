//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNativeDurableFilesystemRejectsHardLinkAliases(t *testing.T) {
	compiler, err := exec.LookPath("cc")
	if err != nil {
		t.Fatal("required Linux host C compiler unavailable")
	}
	root := repositoryRoot(t)
	nativeRoot := filepath.Join(root, "android", "core", "native-jni", "src", "main", "cpp")
	production := filepath.Join(nativeRoot, "kvpn_durable_fs.c")
	if info, err := os.Stat(production); err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 1<<20 {
		t.Fatal("bounded production durable-filesystem source unavailable")
	}
	fixtureRoot := t.TempDir()
	fixture := filepath.Join(fixtureRoot, "hardlink_regression.c")
	if err := os.WriteFile(fixture, []byte(nativeHardLinkRegressionSource), 0o600); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(fixtureRoot, "hardlink_regression")
	compileContext, cancelCompile := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancelCompile()
	compile := exec.CommandContext(
		compileContext,
		compiler,
		"-std=c17",
		"-Wall",
		"-Wextra",
		"-Werror",
		"-O0",
		"-g0",
		"-fno-ident",
		"-ffile-prefix-map="+root+"=.",
		"-fdebug-prefix-map="+root+"=.",
		"-fmacro-prefix-map="+root+"=.",
		"-I",
		nativeRoot,
		fixture,
		production,
		"-o",
		executable,
	)
	if output, err := compile.CombinedOutput(); err != nil {
		t.Fatalf("compile production durable-filesystem regression: %v: %s", err,
			boundedNativeTestOutput(output, root, fixtureRoot))
	}
	runContext, cancelRun := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancelRun()
	run := exec.CommandContext(runContext, executable, fixtureRoot)
	if output, err := run.CombinedOutput(); err != nil {
		t.Fatalf("execute production durable-filesystem regression: %v: %s", err,
			boundedNativeTestOutput(output, root, fixtureRoot))
	}
}

func boundedNativeTestOutput(output []byte, root, temporary string) string {
	const maximum = 4096
	if len(output) > maximum {
		output = output[:maximum]
	}
	value := string(output)
	for _, path := range []string{root, filepath.ToSlash(root), temporary, filepath.ToSlash(temporary)} {
		value = strings.ReplaceAll(value, path, "<test-path>")
	}
	return value
}

const nativeHardLinkRegressionSource = `
#define _GNU_SOURCE
#include "kvpn_durable_fs.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int metadata_zero(const int64_t metadata[6]) {
    for (size_t i = 0; i < 6U; ++i) if (metadata[i] != 0) return 0;
    return 1;
}

static int same_file(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
        a->st_uid == b->st_uid && a->st_mode == b->st_mode &&
        a->st_nlink == b->st_nlink && a->st_size == b->st_size;
}

int main(int argc, char **argv) {
    if (argc != 2) return 10;
    char root[PATH_MAX];
    int length = snprintf(root, sizeof(root), "%s/root", argv[1]);
    if (length <= 0 || (size_t)length >= sizeof(root)) return 11;
    if (mkdir(root, 0700) != 0) return 12;
    int directory = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (directory < 0) return 13;
    int result = 14;
    int record = -1;
    struct stat directory_stat;
    if (fstat(directory, &directory_stat) != 0) goto done;
    struct kvpn_fs_directory supplied = {
        .fd = directory,
        .uid = (int64_t)directory_stat.st_uid,
        .device = (int64_t)directory_stat.st_dev,
        .inode = (int64_t)directory_stat.st_ino,
    };
    record = openat(directory, "record", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (record < 0) { result = 15; goto done; }
    const uint8_t expected = 7U;
    if (write(record, &expected, 1U) != 1) { result = 16; goto done; }
    if (close(record) != 0) { record = -1; result = 17; goto done; }
    record = -1;
    if (linkat(directory, "record", directory, "hard-record", 0) != 0) { result = 18; goto done; }
    struct stat record_before, hard_before;
    if (fstatat(directory, "record", &record_before, AT_SYMLINK_NOFOLLOW) != 0 ||
        fstatat(directory, "hard-record", &hard_before, AT_SYMLINK_NOFOLLOW) != 0 ||
        !same_file(&record_before, &hard_before) || record_before.st_nlink != 2) {
        result = 19; goto done;
    }
    const uint8_t record_leaf[] = "record";
    const uint8_t hard_leaf[] = "hard-record";
    uint8_t output[64];
    size_t output_length = sizeof(output);
    int64_t metadata[6];
    memset(output, 0xa5, sizeof(output));
    memset(metadata, 0x5a, sizeof(metadata));
    if (kvpn_fs_read(&supplied, record_leaf, sizeof(record_leaf) - 1U, sizeof(output),
        output, &output_length, metadata) != KVPN_FS_UNSAFE || output_length != 0 || !metadata_zero(metadata)) {
        result = 20; goto done;
    }
    output_length = sizeof(output);
    memset(output, 0xa5, sizeof(output));
    memset(metadata, 0x5a, sizeof(metadata));
    if (kvpn_fs_read(&supplied, hard_leaf, sizeof(hard_leaf) - 1U, sizeof(output),
        output, &output_length, metadata) != KVPN_FS_UNSAFE || output_length != 0 || !metadata_zero(metadata)) {
        result = 21; goto done;
    }
    struct stat record_after, hard_after;
    if (fstatat(directory, "record", &record_after, AT_SYMLINK_NOFOLLOW) != 0 ||
        fstatat(directory, "hard-record", &hard_after, AT_SYMLINK_NOFOLLOW) != 0 ||
        !same_file(&record_before, &record_after) || !same_file(&hard_before, &hard_after)) {
        result = 22; goto done;
    }
    record = openat(directory, "record", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (record < 0) { result = 23; goto done; }
    uint8_t observed = 0;
    if (read(record, &observed, 1U) != 1 || observed != expected) { result = 24; goto done; }
    uint8_t trailing = 0;
    if (read(record, &trailing, 1U) != 0) { result = 25; goto done; }
    result = 0;

done:
    if (record >= 0 && close(record) != 0 && result == 0) result = 26;
    if (unlinkat(directory, "hard-record", 0) != 0 && errno != ENOENT && result == 0) result = 27;
    if (unlinkat(directory, "record", 0) != 0 && errno != ENOENT && result == 0) result = 28;
    if (close(directory) != 0 && result == 0) result = 29;
    if (rmdir(root) != 0 && result == 0) result = 30;
    return result;
}
`
