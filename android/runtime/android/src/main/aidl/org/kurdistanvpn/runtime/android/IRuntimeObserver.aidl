// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.runtime.android;

oneway interface IRuntimeObserver {
    void onStatus(in byte[] status);
}
