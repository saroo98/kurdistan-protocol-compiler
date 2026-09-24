// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.runtime.android;
import org.kurdistanvpn.runtime.android.IRuntimeObserver;
import android.os.ParcelFileDescriptor;

interface IRuntimeControl {
    boolean registerObserver(int version, IRuntimeObserver observer);
    void unregisterObserver(int version, IRuntimeObserver observer);
    byte[] queryStatus(int version);
    boolean requestAction(int version, long sequence, int action, IRuntimeObserver observer);
    ParcelFileDescriptor requestProxyCredentials(int version, long sequence, IRuntimeObserver observer);
    String settingsTransition(int version, long sequence, int operation, String token, IRuntimeObserver observer);
    long[] requestProbe(int version, long sequence, String operationId, String profileId, int targetId, int timeoutSeconds, IRuntimeObserver observer);
    boolean cancelProbe(int version, long sequence, String operationId, IRuntimeObserver observer);
    long[] requestUpdate(int version, long sequence, String operationId, String profileId, in ParcelFileDescriptor output, IRuntimeObserver observer);
}
