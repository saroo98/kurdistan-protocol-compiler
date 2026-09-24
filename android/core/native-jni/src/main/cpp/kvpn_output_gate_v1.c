// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
#include "kvpn_output_gate_v1.h"
#include <pthread.h>
#include <stddef.h>
#include <string.h>
#include <time.h>
#ifdef KVPN_ANDROID_PLATFORM_INTERNAL_V1
void kvpn_task7_rejection_v1(uint8_t, uint8_t, int32_t);
#define TASK7_PREPARE_REJECTION(s) kvpn_task7_rejection_v1(2,1,(s))
#define TASK7_CALLBACK_REJECTION(p,s) kvpn_task7_rejection_v1(2,(p),(s))
/* Phases 5..15 carry fixed latch subcategories, not native status codes.
 * Every caller holds gate.mutex; the recorder never acquires that mutex. */
#define TASK7_OWNER_LATCH(o,p,s) do { if (!(o)->closed && !(o)->failure) kvpn_task7_rejection_v1(2,(p),(s)); } while (0)
#else
#define TASK7_PREPARE_REJECTION(s) ((void)0)
#define TASK7_CALLBACK_REJECTION(p,s) ((void)0)
#define TASK7_OWNER_LATCH(o,p,s) ((void)0)
#endif

enum { OWNER_COUNT = 64, NORMAL_COUNT = 266, LANE_COUNT = 267 };
typedef struct {
    uint64_t serial, epoch, attempt, child, delivery, deadline;
    int32_t cleanup;
    uint8_t prepared, terminal, invalid, committed, has_deadline;
    uint8_t receipt_kind, claimed, resolved, retired, ended;
} output_lane;
typedef struct {
    uint64_t id, lease, epoch, parent, next_call, retired_attempt, retired_candidate;
    kvpn_output_call_v1 *calls;
    output_lane lanes[LANE_COUNT];
    uint16_t normal_count, control_count, retirement_count, hooks;
    int32_t failure, sink_failure, terminal_reason;
    uint8_t kind, claimed, closed, terminal, native_retired, signal, opening_stage;
    uint64_t platform_signals[2];
    uint8_t platform_signal_borrowed[2];
    void *platform_object, *platform_methods[20];
    kvpn_platform_borrow_v1 *platform_callback, *platform_cancel;
    kvpn_platform_borrow_v1 *platform_queries[2];
    uint64_t platform_call;
    uint8_t platform_clean;
    uint64_t platform_children[3]; /* revision, publication, socket-or-network */
    kvpn_platform_finalize_v1 *finalizing;
} output_owner;
/* The single table guard is never held across Go, Java, payload copies or
 * resource work. Only the two explicitly outside-observer drains may wait. */
static struct {
    pthread_mutex_t mutex;
    pthread_cond_t changed;
    uint64_t next_id;
    output_owner owners[OWNER_COUNT];
} gate = { .mutex = PTHREAD_MUTEX_INITIALIZER, .changed = PTHREAD_COND_INITIALIZER };

static output_owner *owner_find(uint64_t id) {
    if (!id) return NULL;
    for (size_t i = 0; i < OWNER_COUNT; ++i)
        if (gate.owners[i].id == id) return &gate.owners[i];
    return NULL;
}
static kvpn_output_call_v1 *call_find(output_owner *o, uint64_t serial) {
    if (!o || !serial) return NULL;
    for (kvpn_output_call_v1 *c = o->calls; c; c = c->next)
        if (c->serial == serial) return c;
    return NULL;
}
static output_owner *frame_owner(kvpn_output_call_v1 *c) {
    if (!c) return NULL;
    output_owner *o = owner_find(c->owner);
    return call_find(o, c->serial) == c ? o : NULL;
}
static int32_t admit(output_owner *o, kvpn_output_call_v1 *c, uint8_t cls, uint8_t opening) {
    if (!c || frame_owner(c)) return 2;
    if (o->next_call == UINT64_MAX) { TASK7_OWNER_LATCH(o,5,1); o->closed = 1; o->failure = 18; return 18; }
    memset(c, 0, sizeof(*c));
    c->owner = o->id; c->serial = ++o->next_call; c->epoch = o->epoch;
    c->call_class = cls; c->opening = opening;
    c->next = o->calls; o->calls = c;
    if (cls == KVPN_OUTPUT_RETIREMENT_V1) ++o->retirement_count;
    else if (o->kind == 2 && cls == KVPN_OUTPUT_CONTROL_V1) ++o->control_count;
    else ++o->normal_count;
    return 0;
}
int32_t kvpn_output_owner_reserve_v1(uint8_t kind, uint64_t *owner, uint64_t *lease) {
    if (owner) *owner = 0;
    if (lease) *lease = 0;
    if (!owner || !lease || owner == lease || (kind != 1 && kind != 2)) return 2;
    pthread_mutex_lock(&gate.mutex);
    int32_t s = 5;
    if (gate.next_id > UINT64_MAX - 2) s = 18;
    else for (size_t i = 0; i < OWNER_COUNT; ++i) if (!gate.owners[i].id) {
        output_owner *o = &gate.owners[i];
        memset(o, 0, sizeof(*o));
        o->id = ++gate.next_id; o->lease = ++gate.next_id; o->kind = kind;
        *owner = o->id; *lease = o->lease; s = 0; break;
    }
    pthread_mutex_unlock(&gate.mutex);
    return s;
}
int32_t kvpn_output_abandon_unclaimed_v1(uint64_t lease) {
    pthread_mutex_lock(&gate.mutex);
    int32_t s = 3;
    for (size_t i = 0; lease && i < OWNER_COUNT; ++i) {
        output_owner *o = &gate.owners[i];
        if (o->lease == lease && !o->claimed && !o->platform_signals[0] &&
            !o->platform_signals[1] && !o->platform_object && !o->failure &&
            !o->platform_children[0] && !o->platform_children[1] && !o->platform_children[2] &&
            !o->platform_queries[0] && !o->platform_queries[1]) {
            memset(o, 0, sizeof(*o)); s = 0; break;
        }
    }
    pthread_mutex_unlock(&gate.mutex);
    return s;
}
int32_t kvpn_output_owner_release_v1(uint64_t owner) {
    pthread_mutex_lock(&gate.mutex);
    output_owner *o = owner_find(owner);
    int32_t s = 3;
    if (o && !o->calls && !o->hooks && !o->signal && !o->failure &&
        !o->platform_signals[0] && !o->platform_signals[1] && !o->platform_object &&
        !o->platform_children[0] && !o->platform_children[1] && !o->platform_children[2] &&
        !o->platform_queries[0] && !o->platform_queries[1] &&
        (!o->epoch || o->native_retired)) {
        s = 0;
        for (size_t i = 0; i < LANE_COUNT; ++i) if (o->lanes[i].serial) s = 3;
        if (!s) {
            if (o->finalizing) {
                kvpn_platform_finalize_v1 *claim = o->finalizing;
                if (claim->self != claim || claim->owner != o->id || !o->platform_clean) s = 3;
                else claim->released = 1;
            }
            if (!s) memset(o, 0, sizeof(*o));
        }
    }
    pthread_mutex_unlock(&gate.mutex);
    return s;
}
int32_t kvpn_output_begin_open_v1(uint64_t lease, uint8_t kind, kvpn_output_call_v1 *c) {
    pthread_mutex_lock(&gate.mutex);
    int32_t s = 3;
    for (size_t i = 0; lease && i < OWNER_COUNT; ++i) {
        output_owner *o = &gate.owners[i];
        if (o->lease == lease && o->kind == kind && !o->claimed && !o->closed) {
            s = admit(o, c, KVPN_OUTPUT_NORMAL_V1, 1);
            if (!s) { o->claimed = 1; o->opening_stage = 1; }
            break;
        }
    }
    pthread_mutex_unlock(&gate.mutex);
    return s;
}
void kvpn_output_end_v1(kvpn_output_call_v1 *c) {
    pthread_mutex_lock(&gate.mutex);
    output_owner *o = frame_owner(c);
    if (o) {
        if (c->draining) {
            TASK7_OWNER_LATCH(o,5,2);
            if (!o->failure) o->failure = 18;
            pthread_cond_broadcast(&gate.changed);
            pthread_mutex_unlock(&gate.mutex);
            return;
        }
        if (c->bound) {
            output_lane *l = &o->lanes[c->lane];
            if (l->receipt_kind && !l->resolved && !l->committed) {
                l->ended = 1;
                if (!l->retired) { TASK7_OWNER_LATCH(o,5,3); o->failure = 18; o->closed = 1; }
                else if (!l->claimed) memset(l, 0, sizeof(*l));
            } else if (!l->claimed) memset(l, 0, sizeof(*l));
            else { l->ended = 1; TASK7_OWNER_LATCH(o,5,4); o->failure = 18; o->closed = 1; }
        }
        kvpn_output_call_v1 **p = &o->calls;
        while (*p != c) p = &(*p)->next;
        *p = c->next;
        if (c->call_class == KVPN_OUTPUT_RETIREMENT_V1) --o->retirement_count;
        else if (o->kind == 2 && c->call_class == KVPN_OUTPUT_CONTROL_V1) --o->control_count;
        else --o->normal_count;
        memset(c, 0, sizeof(*c));
        pthread_cond_broadcast(&gate.changed);
    }
    pthread_mutex_unlock(&gate.mutex);
}

int32_t kvpn_output_opening_stage_v1(kvpn_output_call_v1 *call, uint8_t holder) {
    pthread_mutex_lock(&gate.mutex);
    output_owner *o = frame_owner(call);
    int32_t status = 3;
    if (o && call->opening && o->opening_stage == 1 && holder <= 1) {
        o->opening_stage = holder ? 3 : 2;
        status = 0;
    }
    pthread_mutex_unlock(&gate.mutex);
    return status;
}
int32_t kvpn_output_opening_published_v1(kvpn_output_call_v1 *call) {
    pthread_mutex_lock(&gate.mutex);
    output_owner *o = frame_owner(call);
    int32_t status = 3;
    if (o && call->opening && call->bound && o->opening_stage == 3 && o->parent &&
        o->lanes[call->lane].committed && !o->failure) {
        o->opening_stage = 4;
        status = 0;
    }
    pthread_mutex_unlock(&gate.mutex);
    return status;
}
static int32_t finalization_claim(uint64_t identity, uint8_t kind,
    uint8_t failed_open, kvpn_platform_finalize_v1 *claim) {
    if (!identity || (kind != 1 && kind != 2) || !claim) return 25;
    pthread_mutex_lock(&gate.mutex);
    for (size_t i = 0; i < OWNER_COUNT; ++i) if (gate.owners[i].finalizing == claim) {
        pthread_mutex_unlock(&gate.mutex);
        return 25;
    }
    memset(claim, 0, sizeof(*claim));
    int32_t status = 25;
    for (size_t i = 0; i < OWNER_COUNT; ++i) {
        output_owner *o = &gate.owners[i];
        if (o->kind != kind || (failed_open ? o->lease : o->parent) != identity) continue;
        uint8_t stage = failed_open ? (o->opening_stage == 2 || o->opening_stage == 3) : o->opening_stage == 4;
        uint8_t busy = o->calls || o->hooks || o->signal || o->finalizing || o->platform_callback ||
            o->platform_cancel || o->platform_queries[0] || o->platform_queries[1] ||
            o->platform_signals[0] || o->platform_signals[1] || o->platform_children[0] ||
            o->platform_children[1] || o->platform_children[2];
        if (!stage || busy || o->failure || !o->claimed || !o->platform_object || o->platform_clean ||
            (o->epoch && !o->native_retired)) break;
        for (size_t lane = 0; lane < LANE_COUNT; ++lane) if (o->lanes[lane].serial) busy = 1;
        if (busy) break;
        claim->self = claim; claim->object = o->platform_object;
        claim->owner = o->id; claim->lease = o->lease; claim->parent = o->parent;
        claim->kind = o->kind; claim->holder = o->opening_stage != 2;
        o->finalizing = claim;
        status = 0;
        break;
    }
    pthread_mutex_unlock(&gate.mutex);
    return status;
}
int32_t kvpn_output_failed_opening_claim_v1(uint64_t lease, uint8_t kind, kvpn_platform_finalize_v1 *claim) {
    return finalization_claim(lease, kind, 1, claim);
}
int32_t kvpn_output_parent_finalize_claim_v1(uint64_t parent, uint8_t kind, kvpn_platform_finalize_v1 *claim) {
    return finalization_claim(parent, kind, 0, claim);
}
int32_t kvpn_output_finalize_unclaim_v1(kvpn_platform_finalize_v1 *claim) {
    if (!claim || claim->self != claim || claim->released) return 25;
    pthread_mutex_lock(&gate.mutex);
    output_owner *o = owner_find(claim->owner);
    int32_t status = 25;
    if (o && o->finalizing == claim && !o->platform_callback && !o->platform_clean) {
        o->finalizing = NULL;
        memset(claim, 0, sizeof(*claim));
        status = 0;
    }
    pthread_mutex_unlock(&gate.mutex);
    return status;
}
int32_t kvpn_output_finalize_finish_v1(kvpn_platform_finalize_v1 *claim, int32_t actual) {
    if (!claim || claim->self != claim) return 25;
    pthread_mutex_lock(&gate.mutex);
    output_owner *o = owner_find(claim->owner);
    int32_t status = !actual && claim->released == 1 ? 0 : 25;
    if (o && o->finalizing == claim) {
        o->finalizing = NULL;
        o->opening_stage = 5;
        TASK7_OWNER_LATCH(o,7,1);
        o->closed = 1;
        if (!o->failure) o->failure = 18;
        status = 25;
    }
    memset(claim, 0, sizeof(*claim));
    pthread_cond_broadcast(&gate.changed);
    pthread_mutex_unlock(&gate.mutex);
    return status;
}

static int32_t maint_status(int32_t s) {
    switch (s) {
    case 0: return 0;
    case 2: return 3;
    case 3: return 4;
    case 5: return 6;
    case 7: return 8;
    case 8: return 9;
    case 12: return 19;
    case 13: return 20;
    default: return 23;
    }
}
static int32_t clock_now(uint64_t *out) {
    if (!out) { TASK7_CALLBACK_REJECTION(3,2); return 2; }
    *out = 0;
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t) || t.tv_sec < 0 || t.tv_nsec < 0 || t.tv_nsec >= 1000000000L) { TASK7_CALLBACK_REJECTION(3,18); return 18; }
    uint64_t seconds = (uint64_t)t.tv_sec;
    if (seconds > (UINT64_MAX - (uint64_t)t.tv_nsec) / 1000000000ULL) { TASK7_CALLBACK_REJECTION(3,18); return 18; }
    *out = seconds * 1000000000ULL + (uint64_t)t.tv_nsec;
    if (!*out) TASK7_CALLBACK_REJECTION(3,18);
    return *out ? 0 : 18;
}
/* Always returns with the guard held, including refusal. Hooks are borrowers
 * while admitted; lookup never invokes the native registry under this guard. */
static output_owner *enter(uint8_t kind, uint64_t owner, uint64_t serial, uint64_t epoch, kvpn_output_call_v1 **call) {
    pthread_mutex_lock(&gate.mutex);
    output_owner *o = owner_find(owner);
    *call = call_find(o, serial);
    if (!o || o->kind != kind || !*call || (*call)->epoch != epoch || (!epoch && !(*call)->opening)) return NULL;
    ++o->hooks;
    return o;
}
static int32_t leave(output_owner *o, int32_t status, uint8_t kind) {
    if (o) --o->hooks;
    pthread_mutex_unlock(&gate.mutex);
    return kind == 2 ? maint_status(status) : status;
}
static int32_t validate(uint8_t kind, uint64_t owner, uint64_t serial, uint64_t epoch) {
    kvpn_output_call_v1 *c;
    output_owner *o = enter(kind, owner, serial, epoch, &c);
    return leave(o, o ? 0 : 3, kind);
}
static int32_t bind_parent(uint8_t kind, uint64_t owner, uint64_t serial, uint64_t epoch) {
    kvpn_output_call_v1 *c;
    output_owner *o = enter(kind, owner, serial, 0, &c);
    int32_t s = 3;
    if (o && epoch && !o->epoch && c->opening && c->expectation && c->expected_kind == 1 && !o->closed) {
        o->epoch = epoch; c->epoch = epoch; s = 0;
    }
    return leave(o, s, kind);
}
static int32_t bind_handle(uint8_t kind, uint64_t owner, uint64_t serial, uint64_t epoch, uint64_t parent) {
    kvpn_output_call_v1 *c;
    output_owner *o = enter(kind, owner, serial, epoch, &c);
    int32_t s = 3;
    if (o && epoch && parent && c->opening && !o->parent) {
        int duplicate = 0;
        for (size_t i = 0; i < OWNER_COUNT; ++i) if (gate.owners[i].parent == parent) duplicate = 1;
        if (!duplicate) { o->parent = parent; s = 0; }
    }
    return leave(o, s, kind);
}
static int32_t begin_parent(uint64_t parent, uint8_t kind, uint8_t cls, kvpn_output_call_v1 *c, uint8_t *absent) {
    if (absent) *absent = 0;
    if (!parent || (kind != 1 && kind != 2) || cls > 2 || !c) return 2;
    pthread_mutex_lock(&gate.mutex);
    output_owner *o = NULL;
    for (size_t i = 0; i < OWNER_COUNT; ++i)
        if (gate.owners[i].parent == parent && gate.owners[i].kind == kind) { o = &gate.owners[i]; break; }
    int32_t s = 3;
    if (!o && absent) *absent = 1;
    if (o) {
        if (cls == 2) {
            if (o->signal) { TASK7_OWNER_LATCH(o,5,7); o->failure = 18; o->closed = 1; s = 18; pthread_cond_broadcast(&gate.changed); }
            else if (o->retirement_count || (kind == 2 && o->control_count)) s = 5;
            else { s = admit(o, c, cls, 0); if (!s) { TASK7_OWNER_LATCH(o,7,3); o->closed = 1; o->terminal = 1; } }
        } else if (!o->closed && !o->failure && (!o->terminal || cls == 1)) {
            if ((kind == 1 && o->normal_count >= NORMAL_COUNT) ||
                (kind == 2 && ((cls == 0 && (o->normal_count || o->control_count || o->retirement_count)) || (cls == 1 && (o->control_count || o->retirement_count))))) s = 5;
            else s = admit(o, c, cls, 0);
        }
    }
    pthread_mutex_unlock(&gate.mutex);
    return s;
}
int32_t kvpn_output_begin_parent_v1(uint64_t parent, uint8_t kind, uint8_t cls, kvpn_output_call_v1 *c) {
    return begin_parent(parent, kind, cls, c, NULL);
}
int32_t kvpn_output_begin_lifecycle_v1(uint64_t parent, uint8_t kind, kvpn_output_call_v1 *c, uint8_t *absent) {
    if (!absent) return 2;
    return begin_parent(parent, kind, KVPN_OUTPUT_RETIREMENT_V1, c, absent);
}
int32_t kvpn_output_expect_receipt_v1(kvpn_output_call_v1 *c, uint8_t kind) {
    pthread_mutex_lock(&gate.mutex);
    output_owner *o = frame_owner(c);
    int32_t s = 3;
    if (o && !c->expectation && !c->bound && kind <= (o->kind == 1 ? 4 : 2) &&
        (!c->opening || kind == 1) && (c->call_class != 2 || kind == 0)) {
        c->expectation = 1; c->expected_kind = kind; s = 0;
    }
    pthread_mutex_unlock(&gate.mutex);
    return s;
}
static int32_t lane_index(uint16_t lane) {
    if (lane > 267 || lane == 5 || lane == 202) return -1;
    return lane - (lane > 5) - (lane > 202);
}
static int32_t bind_lane(uint8_t kind, uint64_t owner, uint64_t serial, uint64_t epoch, uint16_t lane, uint64_t attempt) {
    kvpn_output_call_v1 *c;
    output_owner *o = enter(kind, owner, serial, epoch, &c);
    int32_t s = 3;
    int32_t index = kind == 1 ? lane_index(lane) : lane;
    if (o && c->expectation && epoch && c->call_class != 2 && index >= 0 && (kind == 1 || lane <= 1)) {
        if (kind == 1 && c->call_class == 1 && lane != 1) return leave(o, 3, kind);
        if (kind == 2 && c->call_class == 1 && lane != 1) return leave(o, 3, kind);
        if (o->closed || o->failure) return leave(o, 18, kind);
        if (c->bound) {
            if (c->lane == (uint16_t)index && o->lanes[index].attempt == attempt) return leave(o, 0, kind);
            /* Authenticated-check nested revocation transfers its same frame,
             * before preparation, into the one shared control lane. */
            if (kind != 2 || c->lane != 0 || lane != 1 || o->lanes[0].prepared || o->control_count || o->retirement_count)
                return leave(o, 3, kind);
            memset(&o->lanes[0], 0, sizeof(o->lanes[0]));
            --o->normal_count; ++o->control_count; c->call_class = 1;
        }
        output_lane *l = &o->lanes[index];
        if (l->serial) s = 5;
        else { memset(l, 0, sizeof(*l)); l->serial = serial; l->epoch = epoch; l->attempt = attempt; c->lane = (uint16_t)index; c->bound = 1; s = 0; }
    }
    return leave(o, s, kind);
}
static int32_t prepare_output(uint8_t kind, uint64_t owner, uint64_t serial, uint64_t epoch,
    uint64_t attempt, uint64_t child, uint64_t delivery, uint8_t has_deadline,
    uint64_t sample, uint64_t remaining, uint8_t terminal) {
    kvpn_output_call_v1 *c;
    output_owner *o = enter(kind, owner, serial, epoch, &c);
    int32_t s = 3;
    if (!o || !c->bound || !c->expectation || !epoch || !o->parent) return leave(o, s, kind);
    output_lane *l = &o->lanes[c->lane];
    if (has_deadline > 1 || terminal > 1 || (kind == 2 && delivery) ||
        (terminal && (c->call_class != 1 || c->lane != 1 || child || delivery))) return leave(o, 3, kind);
    if (o->failure || o->closed || l->invalid || l->prepared || (o->terminal && !terminal) ||
        (kind == 1 && attempt && attempt <= o->retired_attempt && !terminal) ||
        (kind == 2 && child && child <= o->retired_candidate)) return leave(o, 3, kind);
    if (kind == 1 && attempt != l->attempt) return leave(o, 3, kind);
    uint64_t deadline = 0, n = 0;
    if (has_deadline) {
        if (!sample || !remaining || sample > UINT64_MAX - remaining || clock_now(&n)) return leave(o, 18, kind);
        deadline = sample + remaining;
        if (sample > n || n >= deadline) return leave(o, 8, kind);
    } else if (!terminal || sample || remaining) return leave(o, 3, kind);
    uint8_t receipt = c->expected_kind;
    if (!receipt && (delivery || (kind == 2 && child))) return leave(o, 3, kind);
    if (receipt == 1 && (child || delivery || !c->opening)) return leave(o, 3, kind);
    if (kind == 1 && ((receipt == 2 && (!child || delivery)) || (receipt == 3 && (child || !delivery)) || (receipt == 4 && !child))) return leave(o, 3, kind);
    if (kind == 1 && receipt == 4 && !delivery) receipt = 0;
    if (kind == 2 && receipt == 2 && !child) receipt = 0;
    l->child = child; l->delivery = delivery; l->has_deadline = has_deadline;
    l->deadline = deadline; l->terminal = terminal; l->receipt_kind = receipt; l->prepared = 1;
    return leave(o, 0, kind);
}
int32_t kvpn_output_try_commit_v1(kvpn_output_call_v1 *c, int32_t native, uint8_t *publish) {
    if (publish) *publish = 0;
    if (!publish) return 2;
    pthread_mutex_lock(&gate.mutex);
    output_owner *o = frame_owner(c);
    int32_t s = 3;
    if (o) {
        output_lane *l = c->bound ? &o->lanes[c->lane] : NULL;
        if (native < 0 || native > 26) { TASK7_OWNER_LATCH(o,5,5); o->failure = 18; o->closed = 1; s = 18; }
        else if (native && native != 19) s = native;
        else if (!l || !l->prepared || l->committed || l->invalid ||
            (l->receipt_kind && (l->claimed || l->resolved || l->retired || l->cleanup)) ||
            o->failure || o->closed || (o->terminal && !l->terminal)) s = o->failure ? o->failure : 3;
        else if (native == 19 && (o->kind != 1 || c->expected_kind != 4 || c->lane < 5 || c->lane >= 197 || !l->child || l->delivery || l->receipt_kind)) s = 18;
        else if (!native && o->kind == 1 && c->expected_kind == 4 && !l->receipt_kind) s = 18;
        else {
            uint64_t n;
            if (l->has_deadline && (clock_now(&n) || n >= l->deadline)) s = 8;
            else { l->committed = 1; *publish = 1; s = native; }
        }
    }
    pthread_mutex_unlock(&gate.mutex);
    return s;
}
int32_t kvpn_output_publication_undelivered_v1(kvpn_output_call_v1 *c) {
    pthread_mutex_lock(&gate.mutex);
    output_owner *o = frame_owner(c);
    output_lane *l = o && c->bound ? &o->lanes[c->lane] : NULL;
    int32_t status = 3;
    if (l && l->prepared && l->committed && !l->invalid && !l->claimed &&
        !l->resolved && !l->cleanup && !o->failure) {
        l->committed = 0;
        l->invalid = 1;
        status = 0;
        pthread_cond_broadcast(&gate.changed);
    }
    pthread_mutex_unlock(&gate.mutex);
    return status;
}
void kvpn_output_note_failure_v1(kvpn_output_call_v1 *c, int32_t failure) {
    pthread_mutex_lock(&gate.mutex);
    output_owner *o = frame_owner(c);
    if (o) {
        TASK7_OWNER_LATCH(o,5,6);
        if (!o->failure) o->failure = failure > 0 && failure <= 26 && failure != 19 && failure != 20 ? failure : 18;
        o->closed = 1;
        /* Only an explicit consumer failure may reopen cleanup after commit:
         * publication was undelivered, and the sticky failure forbids retry. */
        if (c->bound) o->lanes[c->lane].committed = 0;
        pthread_cond_broadcast(&gate.changed);
    }
    pthread_mutex_unlock(&gate.mutex);
}
static void terminal_mark(uint8_t kind, uint64_t owner, uint64_t epoch, uint64_t identity, int32_t reason, uint8_t parent) {
    pthread_mutex_lock(&gate.mutex);
    output_owner *o = owner_find(owner);
    if (o && o->kind == kind && (epoch || reason == -1) && o->epoch == epoch) {
        ++o->hooks;
        if (reason <= 0 || reason > (kind == 1 ? 26 : 23) || (kind == 1 && (reason == 19 || reason == 20))) { TASK7_OWNER_LATCH(o,6,kind == 1 ? (parent ? 1 : 2) : (parent ? 3 : 4)); o->failure = 18; o->closed = 1; }
        if (parent) { if (!o->terminal) o->terminal_reason = reason; o->terminal = 1; }
        else if (kind == 1) { if (identity > o->retired_attempt) o->retired_attempt = identity; }
        else if (identity > o->retired_candidate) o->retired_candidate = identity;
        for (size_t i = 0; i < LANE_COUNT; ++i) {
            output_lane *l = &o->lanes[i];
            if (l->serial && l->prepared && !l->committed && !l->terminal &&
                (parent || (kind == 1 && l->attempt == identity) || (kind == 2 && l->child && l->child == identity))) l->invalid = 1;
        }
        --o->hooks;
        pthread_cond_broadcast(&gate.changed);
    }
    pthread_mutex_unlock(&gate.mutex);
}
static int32_t supersede(uint64_t owner, uint64_t serial, uint64_t epoch) {
    kvpn_output_call_v1 *c;
    output_owner *o = enter(2, owner, serial, epoch, &c);
    int32_t s = 3;
    if (o && c->bound && c->lane == 1 && c->call_class == 1) {
        if (o->lanes[0].serial && !o->lanes[0].committed) o->lanes[0].invalid = 1;
        s = 0;
    }
    return leave(o, s, 2);
}
static output_lane *exact_receipt(output_owner *o, kvpn_output_call_v1 *c, uint8_t kind, uint64_t parent, uint64_t child, uint64_t delivery) {
    if (!o || !c->bound || !kind || parent != o->parent || (o->kind == 2 && delivery)) return NULL;
    output_lane *l = &o->lanes[c->lane];
    return l->prepared && l->receipt_kind == kind && l->child == child && l->delivery == delivery && !l->resolved ? l : NULL;
}
static int32_t claim(uint8_t ns, uint64_t owner, uint64_t serial, uint64_t epoch, uint8_t kind, uint64_t parent, uint64_t child, uint64_t delivery, uint8_t *retired) {
    if (retired) *retired = 0;
    kvpn_output_call_v1 *c;
    output_owner *o = enter(ns, owner, serial, epoch, &c);
    output_lane *l = retired ? exact_receipt(o, c, kind, parent, child, delivery) : NULL;
    int32_t s = 3;
    if (l && !l->committed && !l->claimed && !l->cleanup) {
        l->claimed = 1; l->invalid = 1; *retired = l->retired; s = 0;
    }
    return leave(o, s, ns);
}
static int32_t finish(uint8_t ns, uint64_t owner, uint64_t serial, uint64_t epoch, uint8_t kind, uint64_t parent, uint64_t child, uint64_t delivery, int32_t actual) {
    kvpn_output_call_v1 *c;
    output_owner *o = enter(ns, owner, serial, epoch, &c);
    output_lane *l = exact_receipt(o, c, kind, parent, child, delivery);
    int32_t s = 3;
    if (l && l->claimed) {
        l->claimed = 0;
        if (actual != 0) {
            if (!l->cleanup) l->cleanup = actual > 0 && actual <= (ns == 1 ? 26 : 23) ? actual : (ns == 1 ? 18 : 23);
            TASK7_OWNER_LATCH(o,14,2);
            if (!o->failure) o->failure = 18;
            o->closed = 1; s = 18;
        } else if (l->cleanup) s = 18;
        else { l->resolved = 1; l->retired = 1; s = 0; }
    }
    if (l && l->cleanup && s == 18) {
        /* Receipt cleanup remains in its actual source namespace. */
        int32_t result = l->cleanup;
        --o->hooks;
        pthread_cond_broadcast(&gate.changed);
        pthread_mutex_unlock(&gate.mutex);
        return result;
    }
    return leave(o, s, ns);
}
static void resource_retired(uint8_t ns, uint64_t owner, uint64_t epoch, uint8_t kind, uint64_t parent, uint64_t attempt, uint64_t child, uint64_t delivery, int32_t actual) {
    pthread_mutex_lock(&gate.mutex);
    output_owner *o = owner_find(owner);
    if (o && o->kind == ns && epoch && o->epoch == epoch && parent && o->parent == parent && kind && kind <= (ns == 1 ? 4 : 2) &&
        !(ns == 2 && delivery) && !(kind == 1 && (child || delivery))) {
        ++o->hooks;
        if (kind == 1 && !actual) { o->native_retired = 1; TASK7_OWNER_LATCH(o,14,1); o->closed = 1; }
        for (size_t i = 0; i < LANE_COUNT; ++i) {
            output_lane *l = &o->lanes[i];
            if (!l->receipt_kind || l->epoch != epoch) continue;
            if (kind != 1 && (l->receipt_kind != kind || l->child != child || l->delivery != delivery || (ns == 1 && l->attempt != attempt))) continue;
            if (actual) { if (!l->cleanup) l->cleanup = actual; TASK7_OWNER_LATCH(o,14,2); if (!o->failure) o->failure = 18; o->closed = 1; }
            else if (!l->cleanup) { l->retired = 1; if (l->ended && !l->claimed) memset(l, 0, sizeof(*l)); }
        }
        if (actual && kind == 1) { TASK7_OWNER_LATCH(o,14,3); if (!o->failure) o->failure = 18; o->closed = 1; }
        --o->hooks;
    }
    pthread_mutex_unlock(&gate.mutex);
}

static int32_t prod_validate(uint64_t o,uint64_t c,uint64_t e) {
    int32_t status=validate(1,o,c,e);
    TASK7_CALLBACK_REJECTION(4,status);
    return status;
}
static int32_t maint_validate(uint64_t o,uint64_t c,uint64_t e) { return validate(2,o,c,e); }
static int32_t prod_parent(uint64_t o,uint64_t c,uint64_t e) { return bind_parent(1,o,c,e); }
static int32_t maint_parent(uint64_t o,uint64_t c,uint64_t e) { return bind_parent(2,o,c,e); }
static int32_t prod_handle(uint64_t o,uint64_t c,uint64_t e,uint64_t p) { return bind_handle(1,o,c,e,p); }
static int32_t maint_handle(uint64_t o,uint64_t c,uint64_t e,uint64_t p) { return bind_handle(2,o,c,e,p); }
static int32_t prod_lane(uint64_t o,uint64_t c,uint64_t e,uint16_t l,uint64_t a) {
    int32_t status=bind_lane(1,o,c,e,l,a);
    TASK7_CALLBACK_REJECTION(2,status);
    return status;
}
static int32_t maint_lane(uint64_t o,uint64_t c,uint64_t e,uint8_t l) { return bind_lane(2,o,c,e,l,0); }
static int32_t prod_prepare(uint64_t o,uint64_t c,uint64_t e,uint64_t a,uint64_t h,uint64_t d,uint8_t hd,uint64_t n,uint64_t r,uint8_t t) {
    int32_t status=prepare_output(1,o,c,e,a,h,d,hd,n,r,t);
    TASK7_PREPARE_REJECTION(status);
    return status;
}
static int32_t maint_prepare(uint64_t o,uint64_t c,uint64_t e,uint64_t h,uint8_t hd,uint64_t n,uint64_t r,uint8_t t) { return prepare_output(2,o,c,e,0,h,0,hd,n,r,t); }
static void prod_terminal(uint64_t o,uint64_t e,int32_t r) { terminal_mark(1,o,e,0,r,1); }
static void maint_terminal(uint64_t o,uint64_t e,int32_t r) { terminal_mark(2,o,e,0,r,1); }
static void prod_attempt(uint64_t o,uint64_t e,uint64_t a,int32_t r) { terminal_mark(1,o,e,a,r,0); }
static void maint_candidate(uint64_t o,uint64_t e,uint64_t c,int32_t r) { terminal_mark(2,o,e,c,r,0); }
static int32_t prod_claim(uint64_t o,uint64_t c,uint64_t e,uint8_t k,uint64_t p,uint64_t h,uint64_t d,uint8_t *r) { return claim(1,o,c,e,k,p,h,d,r); }
static int32_t maint_claim(uint64_t o,uint64_t c,uint64_t e,uint8_t k,uint64_t p,uint64_t h,uint64_t d,uint8_t *r) { return claim(2,o,c,e,k,p,h,d,r); }
static int32_t prod_finish(uint64_t o,uint64_t c,uint64_t e,uint8_t k,uint64_t p,uint64_t h,uint64_t d,int32_t r) { return finish(1,o,c,e,k,p,h,d,r); }
static int32_t maint_finish(uint64_t o,uint64_t c,uint64_t e,uint8_t k,uint64_t p,uint64_t h,uint64_t d,int32_t r) { return finish(2,o,c,e,k,p,h,d,r); }
static void prod_retired(uint64_t o,uint64_t e,uint8_t k,uint64_t p,uint64_t a,uint64_t h,uint64_t d,int32_t r) { resource_retired(1,o,e,k,p,a,h,d,r); }
static void maint_retired(uint64_t o,uint64_t e,uint8_t k,uint64_t p,uint64_t h,int32_t r) { resource_retired(2,o,e,k,p,0,h,0,r); }

static const kvpn_output_callbacks_v1 callbacks = {
    .version = 1, .struct_size = sizeof(kvpn_output_callbacks_v1), .monotonic_now_ns = clock_now,
    .prod_validate_invocation = prod_validate, .prod_bind_parent = prod_parent, .prod_bind_handle = prod_handle,
    .prod_bind_lane = prod_lane, .prod_prepare = prod_prepare, .prod_parent_terminal = prod_terminal,
    .prod_attempt_terminal = prod_attempt, .prod_claim_receipt = prod_claim, .prod_finish_receipt = prod_finish, .prod_resource_retired = prod_retired,
    .maint_validate_invocation = maint_validate, .maint_bind_parent = maint_parent, .maint_bind_handle = maint_handle,
    .maint_bind_lane = maint_lane, .maint_supersede_normal = supersede, .maint_prepare = maint_prepare,
    .maint_parent_terminal = maint_terminal, .maint_candidate_terminal = maint_candidate,
    .maint_claim_receipt = maint_claim, .maint_finish_receipt = maint_finish, .maint_resource_retired = maint_retired
};
const kvpn_output_callbacks_v1 *kvpn_output_callbacks_table_v1(void) { return &callbacks; }

#ifdef KVPN_OUTPUT_TEST_V1
/* Host observation only, separate from production layout/owner storage. The
 * accessor cannot take the guard until the real condition wait releases it. */
static uint64_t test_wait_owner;
uint8_t kvpn_output_test_waiting_v1(uint64_t owner) {
    pthread_mutex_lock(&gate.mutex);
    uint8_t waiting = test_wait_owner == owner && owner != 0;
    pthread_mutex_unlock(&gate.mutex);
    return waiting;
}
#endif
static int wait_changed(output_owner *o) {
#ifdef KVPN_OUTPUT_TEST_V1
    test_wait_owner = o->id;
#else
    (void)o;
#endif
    int result = pthread_cond_wait(&gate.changed, &gate.mutex);
#ifdef KVPN_OUTPUT_TEST_V1
    test_wait_owner = 0;
#endif
    return result;
}
int32_t kvpn_platform_install_v1(uint64_t owner, void *object, void *const methods[20]) {
    if (!object || !methods) return 25;
    for (unsigned i = 0; i < 20; ++i) if (!methods[i]) return 25;
    pthread_mutex_lock(&gate.mutex);
    output_owner *o = owner_find(owner);
    int32_t s = 25;
    if (o && !o->claimed && !o->closed && !o->platform_object) {
        o->platform_object = object;
        memcpy(o->platform_methods, methods, sizeof(o->platform_methods));
        s = 0;
    }
    pthread_mutex_unlock(&gate.mutex);
    return s;
}
int32_t kvpn_platform_abandon_owner_v1(uint64_t lease, uint64_t *owner) {
    if (!owner) return 25;
    *owner = 0;
    pthread_mutex_lock(&gate.mutex);
    int32_t s = 25;
    for (size_t i = 0; lease && i < OWNER_COUNT; ++i) {
        output_owner *o = &gate.owners[i];
        if (o->lease == lease && !o->claimed && !o->closed && o->platform_object) {
            TASK7_OWNER_LATCH(o,7,2); o->closed = 1; *owner = o->id; s = 0; break;
        }
    }
    pthread_mutex_unlock(&gate.mutex);
    return s;
}
int32_t kvpn_platform_unclaimed_borrow_v1(uint64_t lease, kvpn_platform_borrow_v1 *borrow) {
    uint64_t owner = 0;
    pthread_mutex_lock(&gate.mutex);
    for (size_t i = 0; lease && i < OWNER_COUNT; ++i) {
        output_owner *o = &gate.owners[i];
        if (o->lease == lease && !o->claimed && !o->closed && !o->failure && o->platform_object) {
            owner = o->id; break;
        }
    }
    pthread_mutex_unlock(&gate.mutex);
    if (!owner || kvpn_platform_enter_v1(owner, 0, 0, borrow)) return 25;
    pthread_mutex_lock(&gate.mutex);
    output_owner *o = owner_find(owner);
    uint8_t valid = o && o->lease == lease && !o->claimed && !o->closed && !o->failure;
    pthread_mutex_unlock(&gate.mutex);
    if (valid) return 0;
    kvpn_platform_leave_v1(borrow, 0);
    return 25;
}
void kvpn_platform_fail_v1(uint64_t owner) {
    pthread_mutex_lock(&gate.mutex);
    output_owner *o = owner_find(owner);
    if (o) { TASK7_OWNER_LATCH(o,8,1); o->closed = 1; if (!o->failure) o->failure = 18; }
    pthread_cond_broadcast(&gate.changed);
    pthread_mutex_unlock(&gate.mutex);
}
int32_t kvpn_platform_enter_v1(uint64_t owner, uint8_t method, uint64_t call, kvpn_platform_borrow_v1 *borrow) {
    if (!borrow || method >= 20) return 25;
    pthread_mutex_lock(&gate.mutex);
    for (size_t i = 0; i < OWNER_COUNT; ++i) {
        if (gate.owners[i].platform_callback == borrow || gate.owners[i].platform_cancel == borrow ||
            gate.owners[i].platform_queries[0] == borrow || gate.owners[i].platform_queries[1] == borrow) {
            pthread_mutex_unlock(&gate.mutex);
            return 25;
        }
    }
    output_owner *o = owner_find(owner);
    int32_t s = 25;
    uint8_t kind_valid = o && !((method == 2 || (method >= 9 && method <= 11)) && o->kind != 1) &&
        !((method == 3 || (method >= 12 && method <= 17)) && o->kind != 2);
    uint8_t needs_context = method == 4 || method == 5 || method == 9 || method == 12 || method == 17 || method == 18;
    if (o && kind_valid && (needs_context ? call != 0 : call == 0) && o->platform_object && !o->platform_clean &&
        (!o->finalizing || method == 19)) {
        if (method == 18) {
            if (!o->platform_callback && !o->platform_cancel && !o->platform_queries[0] && !o->platform_queries[1] && !o->failure) s = 6;
            if (call && o->platform_call == call && !o->platform_cancel && o->platform_callback) {
                o->platform_cancel = borrow;
                s = 0;
            }
        } else if (!o->platform_callback && !o->platform_cancel && !o->platform_queries[0] && !o->platform_queries[1]) {
            uint8_t cleanup = method == 7 || method == 8 || method == 11 || method == 16 || method == 19;
            uint8_t children = o->platform_children[0] || o->platform_children[1] || o->platform_children[2];
            uint8_t handler = o->signal || o->platform_signal_borrowed[0] || o->platform_signal_borrowed[1];
            if ((cleanup || (!o->closed && !o->failure)) && (method != 19 || (!children && !handler))) {
                o->platform_callback = borrow;
                o->platform_call = call;
                if (method == 19) { TASK7_OWNER_LATCH(o,15,1); o->closed = 1; }
                s = 0;
            }
        }
        if (!s) {
            borrow->object = o->platform_object;
            borrow->method = o->platform_methods[method];
            borrow->owner = owner;
            borrow->call = call;
            borrow->method_index = method;
        }
    }
    pthread_mutex_unlock(&gate.mutex);
    return s;
}
int32_t kvpn_platform_leave_v1(kvpn_platform_borrow_v1 *borrow, int32_t failed) {
    if (!borrow) return 25;
    pthread_mutex_lock(&gate.mutex);
    output_owner *o = owner_find(borrow->owner);
    int32_t s = 25;
    if (o && borrow->call == o->platform_call &&
        ((borrow->method_index == 18 && o->platform_cancel == borrow) ||
        (borrow->method_index != 18 && o->platform_callback == borrow))) {
        if (failed) { TASK7_OWNER_LATCH(o,9,borrow->method_index + 1); o->closed = 1; if (!o->failure) o->failure = 18; }
        if (borrow->method_index == 18) o->platform_cancel = NULL;
        else {
            o->platform_callback = NULL;
            if (borrow->method_index == 19 && !failed && !o->failure) {
                if (o->signal || o->platform_signal_borrowed[0] || o->platform_signal_borrowed[1]) {
                    TASK7_OWNER_LATCH(o,9,21);
                    o->failure = 18;
                } else {
                    o->platform_signals[0] = 0;
                    o->platform_signals[1] = 0;
                    o->platform_clean = 1;
                }
            }
        }
        if (!o->platform_callback && !o->platform_cancel && !o->platform_queries[0] && !o->platform_queries[1]) o->platform_call = 0;
        memset(borrow, 0, sizeof(*borrow));
        s = 0;
    }
    pthread_mutex_unlock(&gate.mutex);
    return s;
}
int32_t kvpn_platform_query_enter_v1(uint64_t owner, uint64_t call, kvpn_platform_borrow_v1 *borrow) {
    if (!owner || !call || !borrow) return 25;
    pthread_mutex_lock(&gate.mutex);
    for (size_t i=0;i<OWNER_COUNT;++i) {
        output_owner *entry=&gate.owners[i];
        if (entry->platform_callback==borrow || entry->platform_cancel==borrow ||
            entry->platform_queries[0]==borrow || entry->platform_queries[1]==borrow) {
            pthread_mutex_unlock(&gate.mutex); return 25;
        }
    }
    output_owner *o=owner_find(owner);
    int32_t s=25;
    if (o && o->platform_object && !o->platform_clean && !o->failure && o->platform_call==call &&
        (o->platform_callback || o->platform_cancel)) {
        for (unsigned i=0;i<2;++i) if (!o->platform_queries[i]) {
            o->platform_queries[i]=borrow;
            memset(borrow,0,sizeof(*borrow));
            borrow->object=o->platform_object; borrow->owner=owner; borrow->call=call;
            borrow->method_index=UINT8_MAX; /* query role, never a callback-table index */
            s=0; break;
        }
    }
    pthread_mutex_unlock(&gate.mutex);
    return s;
}
int32_t kvpn_platform_query_leave_v1(kvpn_platform_borrow_v1 *borrow, int32_t failed) {
    if (!borrow) return 25;
    pthread_mutex_lock(&gate.mutex);
    output_owner *o=owner_find(borrow->owner);
    int32_t s=25;
    if (o && borrow->call==o->platform_call && borrow->object==o->platform_object && borrow->method_index==UINT8_MAX) {
        for (unsigned i=0;i<2;++i) if (o->platform_queries[i]==borrow) {
            if (failed) { TASK7_OWNER_LATCH(o,10,1); o->closed=1; if (!o->failure) o->failure=18; }
            o->platform_queries[i]=NULL;
            if (!o->platform_callback && !o->platform_cancel && !o->platform_queries[0] && !o->platform_queries[1]) o->platform_call=0;
            memset(borrow,0,sizeof(*borrow)); s=0; break;
        }
    }
    pthread_cond_broadcast(&gate.changed);
    pthread_mutex_unlock(&gate.mutex);
    return s;
}
int32_t kvpn_platform_detach_v1(uint64_t owner, void **object) {
    if (!object) return 25;
    *object = NULL;
    pthread_mutex_lock(&gate.mutex);
    output_owner *o = owner_find(owner);
    int32_t s = 25;
    if (o && o->platform_clean && o->platform_object && !o->failure &&
        !o->platform_callback && !o->platform_cancel && !o->platform_signals[0] &&
        !o->platform_queries[0] && !o->platform_queries[1] &&
        !o->platform_children[0] && !o->platform_children[1] && !o->platform_children[2] &&
        !o->platform_signals[1] && !o->calls && !o->hooks && !o->signal &&
        (!o->epoch || o->native_retired)) {
        uint8_t receipts = 0;
        for (size_t i = 0; i < LANE_COUNT; ++i) if (o->lanes[i].serial) receipts = 1;
        if (!receipts) {
            *object = o->platform_object;
            o->platform_object = NULL;
            memset(o->platform_methods, 0, sizeof(o->platform_methods));
            s = 0;
        }
    }
    pthread_mutex_unlock(&gate.mutex);
    return s;
}
static int platform_child_index(output_owner *o, uint8_t kind) {
    if (!o) return -1;
    if (kind == 1 || kind == 2) return kind - 1;
    if ((kind == 3 && o->kind == 1) || (kind == 4 && o->kind == 2)) return 2;
    return -1;
}
int32_t kvpn_platform_child_adopt_v1(uint64_t owner, uint8_t kind, uint64_t child) {
    pthread_mutex_lock(&gate.mutex);
    output_owner *o = owner_find(owner);
    int index = platform_child_index(o, kind);
    int32_t s = 25;
    if (index >= 0 && child && !o->platform_children[index]) {
        uint8_t duplicate = 0;
        for (unsigned i = 0; i < 3; ++i) if (o->platform_children[i] == child) duplicate = 1;
        // Partial acquisition remains owned even if invalidation won during Java.
        if (!duplicate) { o->platform_children[index] = child; s = 0; }
    }
    pthread_mutex_unlock(&gate.mutex);
    return s;
}
int32_t kvpn_platform_child_matches_v1(uint64_t owner, uint8_t kind, uint64_t child) {
    pthread_mutex_lock(&gate.mutex);
    output_owner *o = owner_find(owner);
    int index = platform_child_index(o, kind);
    int32_t result = index >= 0 && child && o->platform_children[index] == child;
    pthread_mutex_unlock(&gate.mutex);
    return result;
}
int32_t kvpn_platform_child_retire_v1(uint64_t owner, uint8_t kind, uint64_t child, int32_t actual) {
    pthread_mutex_lock(&gate.mutex);
    output_owner *o = owner_find(owner);
    int index = platform_child_index(o, kind);
    int32_t s = 25;
    if (index >= 0 && child && o->platform_children[index] == child) {
        if (actual) { TASK7_OWNER_LATCH(o,11,kind); o->closed = 1; if (!o->failure) o->failure = 18; }
        else if (!o->failure) {
            int signal = kind == 1 ? 0 : (kind == 2 ? -1 : 1);
            if ((signal >= 0 && o->platform_signal_borrowed[signal]) || (kind == 1 && o->platform_children[1])) {
                TASK7_OWNER_LATCH(o,11,kind + 8);
                o->closed = 1; o->failure = 18;
            } else {
                o->platform_children[index] = 0;
                if (signal >= 0) o->platform_signals[signal] = 0;
                s = 0;
            }
        }
    }
    pthread_mutex_unlock(&gate.mutex);
    return s;
}
static int platform_signal_index(output_owner *o, uint8_t kind) {
    if (!o) return -1;
    if (kind == 1) return 0;
    if ((kind == 2 && o->kind == 1) || (kind == 3 && o->kind == 2)) return 1;
    return -1;
}
int32_t kvpn_platform_signal_install_v1(uint64_t owner, uint8_t kind, uint64_t signal) {
    pthread_mutex_lock(&gate.mutex);
    output_owner *o = owner_find(owner);
    int index = platform_signal_index(o, kind);
    int32_t s = 25;
    if (index >= 0 && signal && !o->closed && !o->failure && !o->platform_signals[index]) {
        o->platform_signals[index] = signal;
        s = 0;
    }
    pthread_mutex_unlock(&gate.mutex);
    return s;
}
int32_t kvpn_platform_signal_borrow_v1(uint64_t owner, uint8_t kind, uint64_t signal) {
    pthread_mutex_lock(&gate.mutex);
    output_owner *o = owner_find(owner);
    int index = platform_signal_index(o, kind);
    int32_t s = 25;
    if (index >= 0 && signal && o->platform_signals[index] == signal && !o->platform_signal_borrowed[index]) {
        o->platform_signal_borrowed[index] = 1;
        s = 0;
    }
    pthread_mutex_unlock(&gate.mutex);
    return s;
}
int32_t kvpn_platform_signal_return_v1(uint64_t owner, uint8_t kind, uint64_t signal) {
    pthread_mutex_lock(&gate.mutex);
    output_owner *o = owner_find(owner);
    int index = platform_signal_index(o, kind);
    int32_t s = 25;
    if (index >= 0 && signal && o->platform_signals[index] == signal && o->platform_signal_borrowed[index]) {
        o->platform_signal_borrowed[index] = 0;
        s = 0;
    }
    pthread_mutex_unlock(&gate.mutex);
    return s;
}
void *kvpn_platform_signal_object_v1(uint64_t owner, uint8_t kind, uint64_t signal) {
    pthread_mutex_lock(&gate.mutex);
    output_owner *o = owner_find(owner);
    int index = platform_signal_index(o, kind);
    void *result = NULL;
    if (index >= 0 && signal && o->platform_signals[index] == signal && o->platform_signal_borrowed[index])
        result = o->platform_object;
    pthread_mutex_unlock(&gate.mutex);
    return result;
}
int32_t kvpn_platform_signal_retire_v1(uint64_t owner, uint8_t kind, uint64_t signal, int32_t actual) {
    pthread_mutex_lock(&gate.mutex);
    output_owner *o = owner_find(owner);
    int index = platform_signal_index(o, kind);
    int32_t s = 25;
    if (index >= 0 && signal && o->platform_signals[index] == signal) {
        if (actual || o->platform_signal_borrowed[index]) {
            TASK7_OWNER_LATCH(o,12,kind + (actual ? 0 : 8));
            o->closed = 1;
            if (!o->failure) o->failure = 18;
        } else if (!o->failure) {
            o->platform_signals[index] = 0;
            s = 0;
        }
    }
    pthread_mutex_unlock(&gate.mutex);
    return s;
}
int32_t kvpn_platform_revision_prefence_v1(uint64_t owner, uint64_t signal) {
    int32_t s = kvpn_platform_signal_borrow_v1(owner, 1, signal);
    if (s) return s;
    s = kvpn_output_revision_prefence_v1(owner);
    int32_t returned = kvpn_platform_signal_return_v1(owner, 1, signal);
    return s ? s : returned;
}
int32_t kvpn_output_revision_prefence_v1(uint64_t owner) {
    pthread_mutex_lock(&gate.mutex);
    output_owner *o = owner_find(owner);
    int32_t s = 25;
    if (o) {
        TASK7_OWNER_LATCH(o,13,1);
        o->closed = 1;
        o->terminal = 1;
        s = o->failure || o->sink_failure ? 25 : 0;
    }
    pthread_mutex_unlock(&gate.mutex);
    return s;
}
int32_t kvpn_output_revision_begin_v1(uint64_t owner) {
    pthread_mutex_lock(&gate.mutex);
    output_owner *o = owner_find(owner);
    int32_t s = 25; /* legacy CodeStateCorrupt, never P1 INCOMPATIBLE */
    if (o) {
        TASK7_OWNER_LATCH(o,13,2);
        o->closed = 1; o->terminal = 1;
        if (o->signal || o->retirement_count || o->failure || o->sink_failure) {
            TASK7_OWNER_LATCH(o,13,3);
            if (!o->failure) o->failure = 18;
            pthread_cond_broadcast(&gate.changed);
        } else { o->signal = 1; s = 0; }
    }
    pthread_mutex_unlock(&gate.mutex);
    return s;
}
int32_t kvpn_output_revision_finish_v1(uint64_t owner, int32_t native_bridge_status) {
    pthread_mutex_lock(&gate.mutex);
    output_owner *o = owner_find(owner);
    int32_t s = 25;
    if (o && o->signal == 2) {
        TASK7_OWNER_LATCH(o,13,4);
        if (!o->failure) o->failure = 18;
        pthread_cond_broadcast(&gate.changed);
    } else if (o && o->signal == 1) {
        o->signal = 2; /* Exactly one finishing handler may become a waiter. */
        if (native_bridge_status != 0) {
            if (!o->sink_failure) o->sink_failure = native_bridge_status;
            TASK7_OWNER_LATCH(o,13,5);
            if (!o->failure) o->failure = 18;
            s = o->sink_failure;
        } else {
            while (!o->failure && !o->sink_failure && (o->normal_count || o->control_count || o->platform_queries[0] || o->platform_queries[1]))
                if (wait_changed(o)) { TASK7_OWNER_LATCH(o,13,6); o->failure = 18; break; }
            s = o->sink_failure ? o->sink_failure : (o->failure ? 25 : 0);
        }
        o->signal = 0;
        pthread_cond_broadcast(&gate.changed);
    }
    pthread_mutex_unlock(&gate.mutex);
    return s;
}
int32_t kvpn_output_retirement_drain_v1(kvpn_output_call_v1 *c, int32_t native_p1) {
    pthread_mutex_lock(&gate.mutex);
    output_owner *o = frame_owner(c);
    int32_t s = 3;
    if (o && c->call_class == 2 && o->retirement_count == 1) {
        if (c->draining) {
            TASK7_OWNER_LATCH(o,13,7);
            if (!o->failure) o->failure = 18;
            pthread_cond_broadcast(&gate.changed);
            s = o->failure;
            pthread_mutex_unlock(&gate.mutex);
            return s;
        }
        c->draining = 1;
        if (native_p1 != 0) {
            TASK7_OWNER_LATCH(o,13,8);
            if (!o->failure) o->failure = native_p1 > 0 && native_p1 <= 26 && native_p1 != 19 && native_p1 != 20 ? native_p1 : 18;
        }
        if (o->signal && !o->failure) { TASK7_OWNER_LATCH(o,13,9); o->failure = 18; }
        while (!o->failure && (o->normal_count || o->control_count || o->platform_queries[0] || o->platform_queries[1]))
            if (wait_changed(o)) { TASK7_OWNER_LATCH(o,13,10); o->failure = 18; break; }
        s = o->failure;
        c->draining = 0;
    }
    pthread_mutex_unlock(&gate.mutex);
    return s;
}
int32_t kvpn_output_layout_v1(uint8_t kind, uint64_t *shared, uint64_t *owner, uint64_t *frames) {
    if (shared) *shared = 0;
    if (owner) *owner = 0;
    if (frames) *frames = 0;
    if (!shared || !owner || !frames || shared == owner || shared == frames || owner == frames || (kind != 1 && kind != 2)) return 2;
    uint64_t count = kind == 1 ? 267 : 2;
    if (sizeof(kvpn_output_call_v1) > UINT64_MAX / count || sizeof(gate) > UINT64_MAX - sizeof(callbacks)) return 18;
    *shared = sizeof(gate) + sizeof(callbacks); /* includes all 64 owner slots */
    *owner = sizeof(output_owner);
    *frames = sizeof(kvpn_output_call_v1) * count;
    return 0;
}
