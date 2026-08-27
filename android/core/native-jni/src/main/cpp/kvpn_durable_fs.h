// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
#ifndef KVPN_DURABLE_FS_H
#define KVPN_DURABLE_FS_H

#include <stddef.h>
#include <stdint.h>

#define KVPN_FS_MAX_BYTES (8U * 1024U * 1024U + 4096U)
#define KVPN_FS_MAX_LEAF 255U
#define KVPN_FS_MAX_ENTRIES 4096U
#define KVPN_FS_ENTRY_BYTES (1U + KVPN_FS_MAX_LEAF + 48U)

enum kvpn_fs_code {
    KVPN_FS_OK = 0, KVPN_FS_ABSENT = 1, KVPN_FS_CONFLICT = 2,
    KVPN_FS_INVALID = 3, KVPN_FS_UNSAFE = 4, KVPN_FS_IO = 5,
    KVPN_FS_UNSUPPORTED = 6, KVPN_FS_MUTATION_UNPROVEN = 7,
    KVPN_FS_CLOSE_UNPROVEN = 8, KVPN_FS_CLOSED = 9
};

struct kvpn_fs_directory { int64_t fd, uid, device, inode; };

/* Borrow only, with caller-owned lifetime/flag serialization. No close, duplicate,
 * path or byte I/O. OK metadata: dev, ino, uid, full FIFO mode, access, nonblock.
 * After an attempted F_SETFL, any ambiguity is MUTATION_UNPROVEN. */
int kvpn_pipe_prepare_borrowed(int64_t fd, int64_t expected_uid,
    int expected_access, int64_t metadata[6]);

/* No pathname root discovery. All names are length-aware ASCII leaves. */
int kvpn_fs_valid_directory(const struct kvpn_fs_directory *directory);
int kvpn_fs_valid_leaf(const uint8_t *leaf, size_t length);
/* Success transfers one owned child FD in metadata[0], followed by dev, ino,
 * uid, mode, nlink. Failure transfers nothing. Parent remains borrowed. */
int kvpn_fs_open_child_directory(const struct kvpn_fs_directory *parent,
    const uint8_t *leaf, size_t leaf_length, const int64_t expected_identity[2], int64_t metadata[6]);
int kvpn_fs_create_child_directory_exclusive(const struct kvpn_fs_directory *parent,
    const uint8_t *leaf, size_t leaf_length, int64_t metadata[6]);
int kvpn_fs_close_directory(int64_t *owned_fd);
int kvpn_fs_read(const struct kvpn_fs_directory *directory, const uint8_t *leaf,
    size_t leaf_length, size_t limit, uint8_t *output, size_t *length, int64_t metadata[6]);
int kvpn_fs_list(const struct kvpn_fs_directory *directory, size_t max_entries,
    uint8_t *output, size_t capacity, size_t *length, int64_t *count);
int kvpn_fs_bootstrap_lock(const struct kvpn_fs_directory *directory,
    const uint8_t *leaf, size_t leaf_length, int64_t metadata[6]);
int kvpn_fs_open_writer(const struct kvpn_fs_directory *directory,
    const uint8_t *leaf, size_t leaf_length, const int64_t lock_identity[2], int64_t session[2]);
/* Session FDs remain owned and locked until kvpn_fs_close, even on failure. */
int kvpn_fs_mutate(int64_t session[2], const struct kvpn_fs_directory *directory,
    const uint8_t *lock_leaf, size_t lock_length, const int64_t lock_identity[2],
    const uint8_t *leaf, size_t leaf_length, const uint8_t *temp, size_t temp_length,
    const int64_t expected_identity[2], const uint8_t *expected, size_t expected_length,
    const uint8_t *replacement, size_t replacement_length, int replacing, size_t limit);
/* Quiesced and closed projection files only. No content or namespace write.
 * Exact expected bytes bind the caller's Kotlin-computed content digest. Both
 * session FDs remain owned/locked until kvpn_fs_close. OK transfers only a
 * verified snapshot; any uncertainty after file synchronization is unproven. */
int kvpn_fs_sync_existing(int64_t session[2], const struct kvpn_fs_directory *directory,
    const uint8_t *lock_leaf, size_t lock_length, const int64_t lock_identity[2],
    const uint8_t *leaf, size_t leaf_length, const int64_t expected_identity[2],
    const uint8_t *expected, size_t expected_length, size_t limit,
    uint8_t *output, size_t *length, int64_t metadata[6]);
int kvpn_fs_close(int64_t session[2]);

#endif
