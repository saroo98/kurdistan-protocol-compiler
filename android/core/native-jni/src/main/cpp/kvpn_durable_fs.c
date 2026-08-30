// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
#define _GNU_SOURCE
#include "kvpn_durable_fs.h"

#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

/* flock is cooperative only. It cannot exclude hostile code with the same UID. */
static int fd_valid(int64_t fd) { return fd >= 0 && fd <= INT_MAX; }
static int identity_valid(const int64_t id[2]) { return id != NULL && id[0] >= 0 && id[1] > 0; }
static void erase(uint8_t *bytes, size_t length) {
    volatile uint8_t *p = bytes;
    while (length-- != 0) *p++ = 0;
}

int kvpn_fs_valid_directory(const struct kvpn_fs_directory *d) {
    return d != NULL && fd_valid(d->fd) && d->uid >= 0 && d->uid < UINT32_MAX && d->device >= 0 && d->inode > 0;
}

int kvpn_fs_valid_leaf(const uint8_t *leaf, size_t length) {
    if (leaf == NULL || length == 0 || length > KVPN_FS_MAX_LEAF ||
        (length == 1 && leaf[0] == '.') || (length == 2 && leaf[0] == '.' && leaf[1] == '.')) return 0;
    for (size_t i = 0; i < length; ++i) {
        uint8_t c = leaf[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
            c == '.' || c == '_' || c == '-')) return 0;
    }
    return 1;
}

static void name_copy(char name[KVPN_FS_MAX_LEAF + 1], const uint8_t *leaf, size_t length) {
    memcpy(name, leaf, length);
    name[length] = '\0';
}

static int io_code(void) {
    if (errno == ENOSYS || errno == EOPNOTSUPP) return KVPN_FS_UNSUPPORTED;
    if (errno == ELOOP || errno == ENOTDIR) return KVPN_FS_UNSAFE;
    return KVPN_FS_IO;
}

/* Android/Linux close releases the descriptor even on EINTR. Never retry it. */
static int close_once(int *fd) {
    if (*fd < 0) return KVPN_FS_OK;
    int owned = *fd;
    *fd = -1;
    return close(owned) == 0 ? KVPN_FS_OK : KVPN_FS_CLOSE_UNPROVEN;
}

static int stat_fd(int fd, struct stat *st) {
    int rc;
    do { rc = fstat(fd, st); } while (rc < 0 && errno == EINTR);
    return rc;
}

static int stat_name(int dir, const char *name, struct stat *st) {
    int rc;
    do { rc = fstatat(dir, name, st, AT_SYMLINK_NOFOLLOW); } while (rc < 0 && errno == EINTR);
    return rc;
}

static int sync_fd(int fd) {
    int rc;
    do { rc = fsync(fd); } while (rc < 0 && errno == EINTR);
    return rc == 0 ? KVPN_FS_OK : io_code();
}

static int open_leaf(int dir, const char *name, int flags) {
    int fd;
    do { fd = openat(dir, name, flags | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK, 0600); }
    while (fd < 0 && errno == EINTR);
    return fd;
}

static int create_leaf(int dir, const char *name) {
    /* No retry: a namespace-creating call with an interrupted result is unproven. */
    return openat(dir, name, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK, 0600);
}

static int same_identity(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino;
}

static int pipe_stat_valid(const struct stat *st, int64_t expected_uid) {
    return S_ISFIFO(st->st_mode) && (st->st_mode & 07777) == 0600 &&
        (uint64_t)st->st_uid == (uint64_t)expected_uid &&
        (uint64_t)st->st_dev <= INT64_MAX && st->st_ino != 0 &&
        (uint64_t)st->st_ino <= INT64_MAX;
}

/* An interrupted nonblocking metadata call cannot spin past the caller's
 * lifetime/deadline indefinitely. Exhaustion remains an ordinary failure. */
#define KVPN_PIPE_MAX_ATTEMPTS 32U

static int pipe_stat(int fd, struct stat *st) {
    int rc;
    unsigned retries = 0;
    do { rc = fstat(fd, st); } while (rc < 0 && errno == EINTR && ++retries < KVPN_PIPE_MAX_ATTEMPTS);
    return rc;
}

static int pipe_flags(int fd) {
    int flags;
    unsigned retries = 0;
    do { flags = fcntl(fd, F_GETFL); } while (flags < 0 && errno == EINTR && ++retries < KVPN_PIPE_MAX_ATTEMPTS);
    return flags;
}

int kvpn_pipe_prepare_borrowed(int64_t fd_value, int64_t expected_uid,
    int expected_access, int64_t metadata[6]) {
    if (metadata == NULL) return KVPN_FS_INVALID;
    memset(metadata, 0, sizeof(int64_t) * 6U);
    if (!fd_valid(fd_value) || expected_uid < 0 || expected_uid >= UINT32_MAX ||
        (expected_access != O_RDONLY && expected_access != O_WRONLY)) return KVPN_FS_INVALID;
    if ((uint64_t)geteuid() != (uint64_t)expected_uid) return KVPN_FS_UNSAFE;
    int fd = (int)fd_value;
    struct stat before, after;
    if (pipe_stat(fd, &before) != 0) return io_code();
    if (!pipe_stat_valid(&before, expected_uid)) return KVPN_FS_UNSAFE;
    int flags = pipe_flags(fd);
    if (flags < 0) return io_code();
    /* Packet-mode, asynchronous signal delivery and path-only handles are not
     * admitted. Nonblocking does not change the pipe's access mode. */
    if ((flags & O_ACCMODE) != expected_access || (flags & ~(O_ACCMODE | O_NONBLOCK)) != 0)
        return KVPN_FS_UNSAFE;
    int changed = 0;
    if ((flags & O_NONBLOCK) == 0) {
        int rc;
        unsigned retries = 0;
        changed = 1;
        do { rc = fcntl(fd, F_SETFL, flags | O_NONBLOCK); }
        while (rc < 0 && errno == EINTR && ++retries < KVPN_PIPE_MAX_ATTEMPTS);
        if (rc < 0) return KVPN_FS_MUTATION_UNPROVEN;
    }
    int observed_flags = pipe_flags(fd);
    if (observed_flags < 0 || pipe_stat(fd, &after) != 0)
        return changed ? KVPN_FS_MUTATION_UNPROVEN : io_code();
    if (!pipe_stat_valid(&after, expected_uid) || !same_identity(&before, &after) ||
        observed_flags != (flags | O_NONBLOCK))
        return changed ? KVPN_FS_MUTATION_UNPROVEN : KVPN_FS_CONFLICT;
    metadata[0] = (int64_t)after.st_dev;
    metadata[1] = (int64_t)after.st_ino;
    metadata[2] = (int64_t)after.st_uid;
    metadata[3] = (int64_t)(after.st_mode & (S_IFMT | 07777));
    metadata[4] = (int64_t)(observed_flags & O_ACCMODE);
    metadata[5] = (observed_flags & O_NONBLOCK) != 0 ? 1 : 0;
    return KVPN_FS_OK;
}

static int supplied_identity(const struct stat *st, const int64_t id[2]) {
    return identity_valid(id) && (uint64_t)st->st_dev == (uint64_t)id[0] && (uint64_t)st->st_ino == (uint64_t)id[1];
}

static int regular(const struct stat *st, int64_t uid, size_t limit) {
    return S_ISREG(st->st_mode) && (st->st_mode & 07777) == 0600 && (uint64_t)st->st_uid == (uint64_t)uid &&
        st->st_nlink == 1 && (uint64_t)st->st_dev <= INT64_MAX && st->st_ino != 0 && (uint64_t)st->st_ino <= INT64_MAX &&
        st->st_size >= 0 && (uint64_t)st->st_size <= limit;
}

static int verify_directory(int fd, const struct kvpn_fs_directory *d) {
    struct stat st;
    if (stat_fd(fd, &st) != 0) return io_code();
    if (!S_ISDIR(st.st_mode) || (st.st_mode & 07777) != 0700 || st.st_nlink < 1 ||
        (uint64_t)st.st_uid != (uint64_t)d->uid || (uint64_t)st.st_dev != (uint64_t)d->device ||
        (uint64_t)st.st_ino != (uint64_t)d->inode) return KVPN_FS_UNSAFE;
    return KVPN_FS_OK;
}

static int duplicate_directory(const struct kvpn_fs_directory *d, int *out) {
    if (!kvpn_fs_valid_directory(d)) return KVPN_FS_INVALID;
    int code = verify_directory((int)d->fd, d);
    if (code != KVPN_FS_OK) return code;
    int fd;
    do { fd = fcntl((int)d->fd, F_DUPFD_CLOEXEC, 0); } while (fd < 0 && errno == EINTR);
    if (fd < 0) return io_code();
    code = verify_directory(fd, d);
    if (code != KVPN_FS_OK) {
        if (close_once(&fd) != KVPN_FS_OK) return KVPN_FS_CLOSE_UNPROVEN;
        return code;
    }
    *out = fd;
    return KVPN_FS_OK;
}

static int verify_name(int dir, const char *name, const struct stat *opened, int64_t uid, size_t limit) {
    struct stat named;
    if (stat_name(dir, name, &named) != 0) return errno == ENOENT ? KVPN_FS_CONFLICT : io_code();
    return regular(&named, uid, limit) && same_identity(&named, opened) ? KVPN_FS_OK : KVPN_FS_UNSAFE;
}

static void metadata_from(const struct stat *st, int64_t metadata[6]) {
    metadata[0] = (int64_t)st->st_dev;
    metadata[1] = (int64_t)st->st_ino;
    metadata[2] = (int64_t)st->st_uid;
    metadata[3] = (int64_t)(st->st_mode & 07777);
    metadata[4] = (int64_t)st->st_nlink;
    metadata[5] = (int64_t)st->st_size;
}

/* Reads exact fstat length then checks EOF; short reads and EINTR are handled. */
static int read_open_file(int fd, int64_t uid, size_t limit, uint8_t *out, size_t *length, struct stat *before) {
    if (stat_fd(fd, before) != 0) return io_code();
    if (!regular(before, uid, limit)) return KVPN_FS_UNSAFE;
    size_t size = (size_t)before->st_size;
    size_t used = 0;
    while (used < size) {
        ssize_t n = read(fd, out + used, size - used);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) return io_code();
        if (n == 0) return KVPN_FS_CONFLICT;
        used += (size_t)n;
    }
    uint8_t trailing;
    ssize_t n;
    do { n = read(fd, &trailing, 1); } while (n < 0 && errno == EINTR);
    if (n < 0) return io_code();
    if (n != 0) return KVPN_FS_CONFLICT;
    struct stat after;
    if (stat_fd(fd, &after) != 0) return io_code();
    if (!regular(&after, uid, limit) || !same_identity(before, &after) || before->st_size != after.st_size ||
        before->st_mtim.tv_sec != after.st_mtim.tv_sec || before->st_mtim.tv_nsec != after.st_mtim.tv_nsec ||
        before->st_ctim.tv_sec != after.st_ctim.tv_sec || before->st_ctim.tv_nsec != after.st_ctim.tv_nsec) return KVPN_FS_CONFLICT;
    *length = size;
    return KVPN_FS_OK;
}

static int read_leaf(int dir, int64_t uid, const char *name, size_t limit, uint8_t *out,
    size_t *length, struct stat *st) {
    int fd = open_leaf(dir, name, O_RDONLY);
    if (fd < 0) return errno == ENOENT ? KVPN_FS_ABSENT : io_code();
    int code = read_open_file(fd, uid, limit, out, length, st);
    if (code == KVPN_FS_OK) code = verify_name(dir, name, st, uid, limit);
    if (close_once(&fd) != KVPN_FS_OK) code = KVPN_FS_CLOSE_UNPROVEN;
    return code;
}

int kvpn_fs_read(const struct kvpn_fs_directory *d, const uint8_t *leaf, size_t leaf_length,
    size_t limit, uint8_t *output, size_t *length, int64_t metadata[6]) {
    if (length != NULL) *length = 0;
    if (metadata != NULL) memset(metadata, 0, 6 * sizeof(int64_t));
    if (!kvpn_fs_valid_directory(d) || !kvpn_fs_valid_leaf(leaf, leaf_length) || limit == 0 ||
        limit > KVPN_FS_MAX_BYTES || output == NULL || length == NULL || metadata == NULL) return KVPN_FS_INVALID;
    int dir = -1;
    int code = duplicate_directory(d, &dir);
    if (code != KVPN_FS_OK) return code;
    char name[KVPN_FS_MAX_LEAF + 1];
    name_copy(name, leaf, leaf_length);
    struct stat st;
    code = read_leaf(dir, d->uid, name, limit, output, length, &st);
    if (code == KVPN_FS_OK || code == KVPN_FS_ABSENT) {
        int checked = verify_directory(dir, d);
        if (checked != KVPN_FS_OK) code = checked;
    }
    if (close_once(&dir) != KVPN_FS_OK) code = KVPN_FS_CLOSE_UNPROVEN;
    if (code == KVPN_FS_OK) metadata_from(&st, metadata);
    else { memset(output, 0, limit); *length = 0; }
    return code;
}

static int same_directory_version(const struct stat *a, const struct stat *b) {
    return same_identity(a, b) && a->st_mtim.tv_sec == b->st_mtim.tv_sec && a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
        a->st_ctim.tv_sec == b->st_ctim.tv_sec && a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}

static void encode_u64(uint8_t *out, uint64_t value) {
    for (int i = 7; i >= 0; --i) { out[i] = (uint8_t)value; value >>= 8; }
}

int kvpn_fs_list(const struct kvpn_fs_directory *d, size_t max_entries,
    uint8_t *output, size_t capacity, size_t *length, int64_t *count) {
    if (length != NULL) *length = 0;
    if (count != NULL) *count = 0;
    if (!kvpn_fs_valid_directory(d) || max_entries == 0 || max_entries > KVPN_FS_MAX_ENTRIES ||
        output == NULL || length == NULL || count == NULL || capacity < max_entries * KVPN_FS_ENTRY_BYTES) return KVPN_FS_INVALID;
    int parent = -1, dir = -1;
    DIR *stream = NULL;
    int code = duplicate_directory(d, &parent);
    if (code != KVPN_FS_OK) return code;
    /* Independent open-file description avoids changing the caller's directory offset. */
    dir = open_leaf(parent, ".", O_RDONLY | O_DIRECTORY);
    if (dir < 0) code = io_code();
    if (close_once(&parent) != KVPN_FS_OK) code = KVPN_FS_CLOSE_UNPROVEN;
    if (code == KVPN_FS_OK) code = verify_directory(dir, d);
    struct stat before, after;
    if (code == KVPN_FS_OK && stat_fd(dir, &before) != 0) code = io_code();
    if (code == KVPN_FS_OK) {
        stream = fdopendir(dir);
        if (stream == NULL) code = io_code();
        /* On success stream owns dir. Keep its integer only for relative inspections. */
    }
    while (code == KVPN_FS_OK) {
        errno = 0;
        struct dirent *entry = readdir(stream);
        if (entry == NULL) {
            if (errno == EINTR) continue;
            if (errno != 0) code = io_code();
            break;
        }
        size_t name_length = strnlen(entry->d_name, KVPN_FS_MAX_LEAF + 1);
        if ((name_length == 1 && entry->d_name[0] == '.') ||
            (name_length == 2 && entry->d_name[0] == '.' && entry->d_name[1] == '.')) continue;
        if (!kvpn_fs_valid_leaf((const uint8_t *)entry->d_name, name_length) || (uint64_t)*count >= max_entries) {
            code = KVPN_FS_UNSAFE;
            break;
        }
        struct stat named, opened;
        if (stat_name(dir, entry->d_name, &named) != 0) { code = io_code(); break; }
        if (!regular(&named, d->uid, KVPN_FS_MAX_BYTES)) { code = KVPN_FS_UNSAFE; break; }
        int file = open_leaf(dir, entry->d_name, O_RDONLY);
        if (file < 0) { code = io_code(); break; }
        if (stat_fd(file, &opened) != 0) code = io_code();
        else if (!regular(&opened, d->uid, KVPN_FS_MAX_BYTES) || !same_identity(&named, &opened) || named.st_size != opened.st_size) code = KVPN_FS_CONFLICT;
        if (code == KVPN_FS_OK) code = verify_name(dir, entry->d_name, &opened, d->uid, KVPN_FS_MAX_BYTES);
        if (close_once(&file) != KVPN_FS_OK) code = KVPN_FS_CLOSE_UNPROVEN;
        if (code != KVPN_FS_OK) break;
        int64_t metadata[6];
        metadata_from(&opened, metadata);
        output[(*length)++] = (uint8_t)name_length;
        memcpy(output + *length, entry->d_name, name_length);
        *length += name_length;
        for (size_t i = 0; i < 6; ++i) { encode_u64(output + *length, (uint64_t)metadata[i]); *length += 8; }
        ++*count;
    }
    if (code == KVPN_FS_OK) code = verify_directory(dir, d);
    if (code == KVPN_FS_OK && stat_fd(dir, &after) != 0) code = io_code();
    if (code == KVPN_FS_OK && !same_directory_version(&before, &after)) code = KVPN_FS_CONFLICT;
    if (stream != NULL) {
        dir = -1;
        /* closedir consumes its descriptor; like close it is never retried. */
        if (closedir(stream) != 0) code = KVPN_FS_CLOSE_UNPROVEN;
    } else if (close_once(&dir) != KVPN_FS_OK) code = KVPN_FS_CLOSE_UNPROVEN;
    if (code != KVPN_FS_OK) { memset(output, 0, *length); *length = 0; *count = 0; }
    return code;
}

static int verify_lock(int dir, int lock, const struct kvpn_fs_directory *d, const char *leaf, const int64_t id[2]) {
    int code = verify_directory(dir, d);
    if (code != KVPN_FS_OK) return code;
    struct stat st;
    if (stat_fd(lock, &st) != 0) return io_code();
    if (!regular(&st, d->uid, 0) || !supplied_identity(&st, id)) return KVPN_FS_UNSAFE;
    return verify_name(dir, leaf, &st, d->uid, 0);
}

int kvpn_fs_close(int64_t session[2]) {
    if (session == NULL || !fd_valid(session[0]) || !fd_valid(session[1]) || session[0] == session[1]) return KVPN_FS_INVALID;
    int dir = (int)session[0], lock = (int)session[1];
    session[0] = session[1] = -1;
    int a = close_once(&dir);
    int b = close_once(&lock); /* Lock is held until this final close. */
    return a == KVPN_FS_OK && b == KVPN_FS_OK ? KVPN_FS_OK : KVPN_FS_CLOSE_UNPROVEN;
}

int kvpn_fs_open_writer(const struct kvpn_fs_directory *d, const uint8_t *leaf, size_t leaf_length,
    const int64_t id[2], int64_t session[2]) {
    if (session != NULL) session[0] = session[1] = -1;
    if (!kvpn_fs_valid_directory(d) || !kvpn_fs_valid_leaf(leaf, leaf_length) || !identity_valid(id) || session == NULL) return KVPN_FS_INVALID;
    char name[KVPN_FS_MAX_LEAF + 1];
    name_copy(name, leaf, leaf_length);
    int dir = -1, lock = -1;
    int code = duplicate_directory(d, &dir);
    if (code != KVPN_FS_OK) return code;
    lock = open_leaf(dir, name, O_RDWR); /* Restoration never creates a lock. */
    if (lock < 0) code = errno == ENOENT ? KVPN_FS_ABSENT : io_code();
    if (code == KVPN_FS_OK) code = verify_lock(dir, lock, d, name, id);
    if (code == KVPN_FS_OK) {
        int rc;
        do { rc = flock(lock, LOCK_EX | LOCK_NB); } while (rc < 0 && errno == EINTR);
        if (rc != 0) code = errno == EWOULDBLOCK ? KVPN_FS_CONFLICT : io_code();
    }
    if (code == KVPN_FS_OK) code = verify_lock(dir, lock, d, name, id);
    if (code == KVPN_FS_OK) { session[0] = dir; session[1] = lock; return code; }
    int a = close_once(&dir), b = close_once(&lock);
    return a == KVPN_FS_OK && b == KVPN_FS_OK ? code : KVPN_FS_CLOSE_UNPROVEN;
}

static int child_directory_stat(const struct stat *st, const struct kvpn_fs_directory *parent) {
    return S_ISDIR(st->st_mode) && (st->st_mode & 07777) == 0700 &&
        (uint64_t)st->st_uid == (uint64_t)parent->uid && st->st_nlink >= 1 &&
        (uint64_t)st->st_nlink <= INT64_MAX && (uint64_t)st->st_dev == (uint64_t)parent->device &&
        st->st_ino != 0 && (uint64_t)st->st_ino <= INT64_MAX && (uint64_t)st->st_ino != (uint64_t)parent->inode;
}

static int verify_child_name(int parent_fd, const struct kvpn_fs_directory *parent,
    const char *name, const struct stat *opened) {
    struct stat named;
    if (stat_name(parent_fd, name, &named) != 0) return errno == ENOENT ? KVPN_FS_CONFLICT : io_code();
    return child_directory_stat(&named, parent) && same_identity(&named, opened) ? KVPN_FS_OK : KVPN_FS_UNSAFE;
}

static int open_child_owned(int parent_fd, const struct kvpn_fs_directory *parent, const char *name,
    const int64_t expected[2], int *owned, struct stat *opened) {
    struct stat named;
    if (stat_name(parent_fd, name, &named) != 0) return errno == ENOENT ? KVPN_FS_ABSENT : io_code();
    if (!child_directory_stat(&named, parent)) return KVPN_FS_UNSAFE;
    if (expected != NULL && !supplied_identity(&named, expected)) return KVPN_FS_CONFLICT;
    int fd = open_leaf(parent_fd, name, O_RDONLY | O_DIRECTORY);
    if (fd < 0) return errno == ENOENT ? KVPN_FS_CONFLICT : io_code();
    int code = stat_fd(fd, opened) == 0 ? KVPN_FS_OK : io_code();
    if (code == KVPN_FS_OK && (!child_directory_stat(opened, parent) || !same_identity(&named, opened))) code = KVPN_FS_UNSAFE;
    if (code == KVPN_FS_OK) code = verify_child_name(parent_fd, parent, name, opened);
    if (code == KVPN_FS_OK) { *owned = fd; return code; }
    return close_once(&fd) == KVPN_FS_OK ? code : KVPN_FS_CLOSE_UNPROVEN;
}

static void child_metadata(int owned, const struct stat *st, int64_t metadata[6]) {
    metadata[0] = owned;
    metadata[1] = (int64_t)st->st_dev;
    metadata[2] = (int64_t)st->st_ino;
    metadata[3] = (int64_t)st->st_uid;
    metadata[4] = (int64_t)(st->st_mode & 07777);
    metadata[5] = (int64_t)st->st_nlink;
}

int kvpn_fs_open_child_directory(const struct kvpn_fs_directory *parent, const uint8_t *leaf,
    size_t leaf_length, const int64_t expected[2], int64_t metadata[6]) {
    if (metadata != NULL) memset(metadata, 0, 6 * sizeof(int64_t));
    if (!kvpn_fs_valid_directory(parent) || !kvpn_fs_valid_leaf(leaf, leaf_length) || metadata == NULL ||
        (expected != NULL && !identity_valid(expected))) return KVPN_FS_INVALID;
    int dir = -1, child = -1;
    struct stat opened;
    char name[KVPN_FS_MAX_LEAF + 1];
    name_copy(name, leaf, leaf_length);
    int code = duplicate_directory(parent, &dir);
    if (code != KVPN_FS_OK) return code;
    code = open_child_owned(dir, parent, name, expected, &child, &opened);
    if (code == KVPN_FS_OK || code == KVPN_FS_ABSENT) {
        int checked = verify_directory(dir, parent);
        if (checked != KVPN_FS_OK) code = checked;
    }
    if (close_once(&dir) != KVPN_FS_OK) code = KVPN_FS_CLOSE_UNPROVEN;
    if (code == KVPN_FS_OK) child_metadata(child, &opened, metadata);
    else if (close_once(&child) != KVPN_FS_OK) code = KVPN_FS_CLOSE_UNPROVEN;
    return code;
}

int kvpn_fs_create_child_directory_exclusive(const struct kvpn_fs_directory *parent,
    const uint8_t *leaf, size_t leaf_length, int64_t metadata[6]) {
    if (metadata != NULL) memset(metadata, 0, 6 * sizeof(int64_t));
    if (!kvpn_fs_valid_directory(parent) || !kvpn_fs_valid_leaf(leaf, leaf_length) || metadata == NULL) return KVPN_FS_INVALID;
    int dir = -1, child = -1, changed = 0;
    struct stat opened;
    char name[KVPN_FS_MAX_LEAF + 1];
    name_copy(name, leaf, leaf_length);
    int code = duplicate_directory(parent, &dir);
    if (code != KVPN_FS_OK) return code;
    /* Verify and synchronize the supplied parent before the exclusive namespace
     * change. Durability is proven on the actual child and parent afterward. */
    code = sync_fd(dir);
    if (code == KVPN_FS_OK) code = verify_directory(dir, parent);
    if (code == KVPN_FS_OK) {
        /* mkdirat is exclusive. Never retry a possibly completed namespace call. */
        int rc = mkdirat(dir, name, 0700);
        if (rc != 0 && errno == EEXIST) code = KVPN_FS_CONFLICT;
        else {
            changed = 1;
            if (rc != 0) code = KVPN_FS_MUTATION_UNPROVEN;
        }
    }
    if (code == KVPN_FS_OK) code = open_child_owned(dir, parent, name, NULL, &child, &opened);
    if (code == KVPN_FS_OK) code = sync_fd(child);
    if (code == KVPN_FS_OK) code = verify_child_name(dir, parent, name, &opened);
    if (code == KVPN_FS_OK) code = sync_fd(dir);
    if (code == KVPN_FS_OK) {
        int64_t identity[2] = {(int64_t)opened.st_dev, (int64_t)opened.st_ino};
        if (close_once(&child) != KVPN_FS_OK) code = KVPN_FS_CLOSE_UNPROVEN;
        if (code == KVPN_FS_OK) code = open_child_owned(dir, parent, name, identity, &child, &opened);
    }
    if (code == KVPN_FS_OK) code = verify_directory(dir, parent);
    if (close_once(&dir) != KVPN_FS_OK) code = KVPN_FS_CLOSE_UNPROVEN;
    if (code == KVPN_FS_OK) child_metadata(child, &opened, metadata);
    else {
        if (close_once(&child) != KVPN_FS_OK) code = KVPN_FS_CLOSE_UNPROVEN;
        if (changed) code = KVPN_FS_MUTATION_UNPROVEN;
    }
    return code;
}

int kvpn_fs_close_directory(int64_t *owned_fd) {
    if (owned_fd == NULL || !fd_valid(*owned_fd)) return KVPN_FS_INVALID;
    int fd = (int)*owned_fd;
    *owned_fd = -1;
    return close_once(&fd);
}

int kvpn_fs_bootstrap_lock(const struct kvpn_fs_directory *d, const uint8_t *leaf,
    size_t leaf_length, int64_t metadata[6]) {
    if (metadata != NULL) memset(metadata, 0, 6 * sizeof(int64_t));
    if (!kvpn_fs_valid_directory(d) || !kvpn_fs_valid_leaf(leaf, leaf_length) || metadata == NULL) return KVPN_FS_INVALID;
    int dir = -1, fd = -1, changed = 0;
    struct stat st;
    char name[KVPN_FS_MAX_LEAF + 1];
    name_copy(name, leaf, leaf_length);
    int code = duplicate_directory(d, &dir);
    if (code != KVPN_FS_OK) return code;
    code = sync_fd(dir);
    if (code == KVPN_FS_OK) {
        fd = create_leaf(dir, name);
        if (fd < 0 && errno == EEXIST) code = KVPN_FS_CONFLICT;
        else {
            changed = 1;
            if (fd < 0) code = KVPN_FS_MUTATION_UNPROVEN;
        }
    }
    if (code == KVPN_FS_OK && stat_fd(fd, &st) != 0) code = io_code();
    if (code == KVPN_FS_OK && !regular(&st, d->uid, 0)) code = KVPN_FS_UNSAFE;
    if (code == KVPN_FS_OK) {
        int rc;
        do { rc = flock(fd, LOCK_EX | LOCK_NB); } while (rc < 0 && errno == EINTR);
        if (rc != 0) code = io_code();
    }
    if (code == KVPN_FS_OK) code = sync_fd(fd);
    if (code == KVPN_FS_OK) code = verify_name(dir, name, &st, d->uid, 0);
    if (code == KVPN_FS_OK) code = sync_fd(dir);
    if (code == KVPN_FS_OK) {
        uint8_t unused = 0;
        size_t length = 0;
        struct stat reopened;
        code = read_leaf(dir, d->uid, name, 0, &unused, &length, &reopened);
        if (code == KVPN_FS_OK && !same_identity(&st, &reopened)) code = KVPN_FS_CONFLICT;
    }
    if (code == KVPN_FS_OK) code = verify_directory(dir, d);
    if (close_once(&dir) != KVPN_FS_OK) code = KVPN_FS_CLOSE_UNPROVEN;
    if (close_once(&fd) != KVPN_FS_OK) code = KVPN_FS_CLOSE_UNPROVEN;
    if (code == KVPN_FS_OK) metadata_from(&st, metadata);
    else if (changed) code = KVPN_FS_MUTATION_UNPROVEN;
    return code;
}

static int expected_old(int dir, int64_t uid, const char *name, const int64_t id[2],
    const uint8_t *expected, size_t expected_length, size_t limit, uint8_t *scratch) {
    struct stat st;
    size_t length = 0;
    int code = read_leaf(dir, uid, name, limit, scratch, &length, &st);
    if (id == NULL) return code == KVPN_FS_ABSENT ? KVPN_FS_OK : (code == KVPN_FS_OK ? KVPN_FS_CONFLICT : code);
    if (code == KVPN_FS_ABSENT) return KVPN_FS_CONFLICT;
    if (code != KVPN_FS_OK) return code;
    return supplied_identity(&st, id) && length == expected_length &&
        (length == 0 || memcmp(scratch, expected, length) == 0) ? KVPN_FS_OK : KVPN_FS_CONFLICT;
}

static int write_all(int fd, const uint8_t *bytes, size_t length) {
    size_t used = 0;
    while (used < length) {
        ssize_t n = write(fd, bytes + used, length - used);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) return io_code();
        if (n == 0) return KVPN_FS_IO;
        used += (size_t)n;
    }
    return KVPN_FS_OK;
}

int kvpn_fs_sync_existing(int64_t session[2], const struct kvpn_fs_directory *d,
    const uint8_t *lock_leaf, size_t lock_length, const int64_t lock_id[2],
    const uint8_t *leaf, size_t leaf_length, const int64_t expected_id[2],
    const uint8_t *expected, size_t expected_length, size_t limit,
    uint8_t *output, size_t *length, int64_t metadata[6]) {
    if (length != NULL) *length = 0;
    if (metadata != NULL) memset(metadata, 0, 6 * sizeof(int64_t));
    if (session == NULL || !fd_valid(session[0]) || !fd_valid(session[1]) || session[0] == session[1] ||
        !kvpn_fs_valid_directory(d) || !identity_valid(lock_id) || !identity_valid(expected_id) ||
        !kvpn_fs_valid_leaf(lock_leaf, lock_length) || !kvpn_fs_valid_leaf(leaf, leaf_length) ||
        limit == 0 || limit > KVPN_FS_MAX_BYTES || expected_length > limit ||
        (expected_length != 0 && expected == NULL) || output == NULL || length == NULL || metadata == NULL) return KVPN_FS_INVALID;
    /* JNI supplies separate owned buffers. Reject overlap also at the C API so
     * the read destination can never overwrite its own expected-state oracle. */
    uintptr_t expected_start = (uintptr_t)expected, output_start = (uintptr_t)output;
    if (output_start > UINTPTR_MAX - limit || (expected_length != 0 &&
        (expected_start > UINTPTR_MAX - expected_length ||
        (expected_start < output_start + limit && output_start < expected_start + expected_length)))) return KVPN_FS_INVALID;
    int dir = (int)session[0], lock = (int)session[1], file = -1, synchronization_started = 0;
    char name[KVPN_FS_MAX_LEAF + 1], lock_name[KVPN_FS_MAX_LEAF + 1];
    struct stat opened, reopened;
    size_t observed_length = 0;
    name_copy(name, leaf, leaf_length);
    name_copy(lock_name, lock_leaf, lock_length);
    if (strcmp(name, lock_name) == 0) return KVPN_FS_INVALID;
    int code = verify_lock(dir, lock, d, lock_name, lock_id);
    if (code == KVPN_FS_OK) code = sync_fd(lock);
    if (code == KVPN_FS_OK) code = sync_fd(dir);
    if (code != KVPN_FS_OK) goto done;
    /* The approved caller must retain Room/DataStore write and close errors,
     * and prove quiescence before entry. A new FD cannot recover lost earlier
     * writeback-error history, and flock does not constrain hostile same-UID code. */
    file = open_leaf(dir, name, O_RDONLY);
    if (file < 0) { code = errno == ENOENT ? KVPN_FS_CONFLICT : io_code(); goto done; }
    code = read_open_file(file, d->uid, limit, output, &observed_length, &opened);
    if (code == KVPN_FS_OK && (!supplied_identity(&opened, expected_id) || observed_length != expected_length ||
        (observed_length != 0 && memcmp(output, expected, observed_length) != 0))) code = KVPN_FS_CONFLICT;
    if (code == KVPN_FS_OK) code = verify_name(dir, name, &opened, d->uid, limit);
    if (code == KVPN_FS_OK) code = verify_lock(dir, lock, d, lock_name, lock_id);
    if (code != KVPN_FS_OK) goto done;
    synchronization_started = 1;
    code = sync_fd(file);
    if (code == KVPN_FS_OK) code = verify_name(dir, name, &opened, d->uid, limit);
    /* close_once consumes the FD before calling close and never retries EINTR. */
    if (close_once(&file) != KVPN_FS_OK) code = KVPN_FS_CLOSE_UNPROVEN;
    if (code == KVPN_FS_OK) code = sync_fd(dir);
    if (code != KVPN_FS_OK) goto done;
    code = read_leaf(dir, d->uid, name, limit, output, &observed_length, &reopened);
    if (code == KVPN_FS_OK && (!same_identity(&opened, &reopened) || !supplied_identity(&reopened, expected_id) ||
        observed_length != expected_length || (observed_length != 0 && memcmp(output, expected, observed_length) != 0))) code = KVPN_FS_CONFLICT;
    if (code == KVPN_FS_OK) code = verify_name(dir, name, &reopened, d->uid, limit);
    if (code == KVPN_FS_OK) code = verify_lock(dir, lock, d, lock_name, lock_id);
done:
    if (close_once(&file) != KVPN_FS_OK) code = KVPN_FS_CLOSE_UNPROVEN;
    if (code == KVPN_FS_OK) {
        metadata_from(&reopened, metadata);
        *length = observed_length;
    } else {
        erase(output, limit);
        *length = 0;
        if (synchronization_started || code == KVPN_FS_CLOSE_UNPROVEN) code = KVPN_FS_MUTATION_UNPROVEN;
    }
    return code;
}

int kvpn_fs_mutate(int64_t session[2], const struct kvpn_fs_directory *d,
    const uint8_t *lock_leaf, size_t lock_length, const int64_t lock_id[2],
    const uint8_t *leaf, size_t leaf_length, const uint8_t *temp, size_t temp_length,
    const int64_t expected_id[2], const uint8_t *expected, size_t expected_length,
    const uint8_t *replacement, size_t replacement_length, int replacing, size_t limit) {
    if (session == NULL || !fd_valid(session[0]) || !fd_valid(session[1]) || session[0] == session[1]) return KVPN_FS_INVALID;
    int code = KVPN_FS_INVALID, changed = 0, temporary_fd = -1;
    uint8_t *scratch = NULL;
    int dir = (int)session[0], lock = (int)session[1];
    char name[KVPN_FS_MAX_LEAF + 1], temporary[KVPN_FS_MAX_LEAF + 1], lock_name[KVPN_FS_MAX_LEAF + 1];
    struct stat temporary_stat;
    if (!kvpn_fs_valid_directory(d) || !identity_valid(lock_id) || !kvpn_fs_valid_leaf(lock_leaf, lock_length) ||
        !kvpn_fs_valid_leaf(leaf, leaf_length) || limit == 0 || limit > KVPN_FS_MAX_BYTES ||
        expected_length > limit || replacement_length > limit || (expected_length != 0 && expected == NULL) ||
        (expected_id != NULL && !identity_valid(expected_id)) || (expected_id == NULL && expected_length != 0) ||
        (replacing != 0 && replacing != 1) || (!replacing && (expected_id == NULL || replacement != NULL || replacement_length != 0 || temp != NULL || temp_length != 0)) ||
        (replacing && (!kvpn_fs_valid_leaf(temp, temp_length) || (replacement_length != 0 && replacement == NULL)))) goto done;
    name_copy(name, leaf, leaf_length);
    name_copy(lock_name, lock_leaf, lock_length);
    if (strcmp(name, lock_name) == 0) goto done;
    if (replacing) {
        name_copy(temporary, temp, temp_length);
        if (strcmp(temporary, name) == 0 || strcmp(temporary, lock_name) == 0) goto done;
    }
    code = verify_lock(dir, lock, d, lock_name, lock_id);
    if (code != KVPN_FS_OK) goto done;
    code = sync_fd(lock); /* Regular-file and directory fsync capability before any change. */
    if (code == KVPN_FS_OK) code = sync_fd(dir);
    if (code != KVPN_FS_OK) goto done;
    scratch = malloc(limit);
    if (scratch == NULL) { code = KVPN_FS_IO; goto done; }
    code = expected_old(dir, d->uid, name, expected_id, expected, expected_length, limit, scratch);
    if (code != KVPN_FS_OK) goto done;
    if (replacing) {
        temporary_fd = create_leaf(dir, temporary);
        if (temporary_fd < 0 && errno == EEXIST) { code = KVPN_FS_CONFLICT; goto done; }
        changed = 1;
        if (temporary_fd < 0) { code = KVPN_FS_MUTATION_UNPROVEN; goto done; }
        if (stat_fd(temporary_fd, &temporary_stat) != 0) { code = io_code(); goto done; }
        if (!regular(&temporary_stat, d->uid, 0)) { code = KVPN_FS_UNSAFE; goto done; }
        code = write_all(temporary_fd, replacement, replacement_length);
        if (code == KVPN_FS_OK) code = sync_fd(temporary_fd);
        if (code == KVPN_FS_OK) code = verify_name(dir, temporary, &temporary_stat, d->uid, limit);
        if (close_once(&temporary_fd) != KVPN_FS_OK) code = KVPN_FS_CLOSE_UNPROVEN;
        if (code != KVPN_FS_OK) goto done;
        struct stat reopened;
        size_t length = 0;
        code = read_leaf(dir, d->uid, temporary, limit, scratch, &length, &reopened);
        if (code == KVPN_FS_OK && (!same_identity(&temporary_stat, &reopened) || length != replacement_length ||
            (length != 0 && memcmp(scratch, replacement, length) != 0))) code = KVPN_FS_CONFLICT;
        if (code != KVPN_FS_OK) goto done;
        code = expected_old(dir, d->uid, name, expected_id, expected, expected_length, limit, scratch);
        if (code == KVPN_FS_OK) code = verify_lock(dir, lock, d, lock_name, lock_id);
        if (code == KVPN_FS_OK) code = verify_name(dir, temporary, &temporary_stat, d->uid, limit);
        if (code != KVPN_FS_OK) goto done;
        /* Namespace syscalls are not retried after ambiguous errors. */
        if (renameat(dir, temporary, dir, name) != 0) { code = KVPN_FS_MUTATION_UNPROVEN; goto done; }
        code = sync_fd(dir);
        if (code != KVPN_FS_OK) goto done;
        code = read_leaf(dir, d->uid, name, limit, scratch, &length, &reopened);
        if (code == KVPN_FS_OK && (!same_identity(&temporary_stat, &reopened) || length != replacement_length ||
            (length != 0 && memcmp(scratch, replacement, length) != 0))) code = KVPN_FS_CONFLICT;
    } else {
        code = verify_lock(dir, lock, d, lock_name, lock_id);
        if (code != KVPN_FS_OK) goto done;
        changed = 1; /* A failed namespace syscall has no proof of no change. */
        if (unlinkat(dir, name, 0) != 0) { code = KVPN_FS_MUTATION_UNPROVEN; goto done; }
        code = sync_fd(dir);
        if (code == KVPN_FS_OK) {
            struct stat absent;
            if (stat_name(dir, name, &absent) == 0) code = KVPN_FS_CONFLICT;
            else if (errno != ENOENT) code = io_code();
        }
    }
    if (code == KVPN_FS_OK) code = verify_lock(dir, lock, d, lock_name, lock_id);
done:
    if (scratch != NULL) { erase(scratch, limit); free(scratch); }
    if (close_once(&temporary_fd) != KVPN_FS_OK) code = KVPN_FS_CLOSE_UNPROVEN;
    if (changed && code != KVPN_FS_OK) return KVPN_FS_MUTATION_UNPROVEN;
    if (code == KVPN_FS_CLOSE_UNPROVEN) return KVPN_FS_MUTATION_UNPROVEN;
    return code;
}
