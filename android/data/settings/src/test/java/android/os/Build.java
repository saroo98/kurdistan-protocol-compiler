// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package android.os;

/** Host-only API identity. DataStore must exercise its API 26+ NIO file moves,
 * matching this module's minimum API, instead of the SDK jar's API 0 fallback.
 * Actual Android storage is independently exercised by device migration tests. */
public final class Build {
    public static final class VERSION {
        public static final int SDK_INT = 26;
    }
}
