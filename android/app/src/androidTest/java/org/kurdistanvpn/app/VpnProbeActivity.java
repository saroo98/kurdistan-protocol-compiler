// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.app;

import android.app.Activity;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.os.Bundle;
import android.os.Process;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;

public final class VpnProbeActivity extends Activity {
    public static final String ACTION_RESULT = "org.kurdistanvpn.test.VPN_PROBE_RESULT";
    public static final String EXTRA_TOKEN = "token";
    public static final String EXTRA_SUCCESS = "success";
    public static final String EXTRA_TARGET_PACKAGE = "target-package";
    public static final String EXTRA_UNDERLAY_TARGET_ADDRESS = "underlay-target-address";
    public static final String EXTRA_UNDERLAY_TARGET_PORT = "underlay-target-port";
    public static final String EXTRA_BYPASS_BLOCKED = "bypass-blocked";
    public static final String EXTRA_COVERAGE_GAP = "coverage-gap";
    public static final String EXTRA_PROBE_PACKAGE = "probe-package";
    public static final String EXTRA_PROBE_UID = "probe-uid";
    private static final long PROBE_DEADLINE_NANOS = TimeUnit.SECONDS.toNanos(5);
    private static final int ATTEMPT_TIMEOUT_MILLIS = 750;
    private static final int UNDERLAY_ATTEMPT_TIMEOUT_MILLIS = 2_000;
    private static final int MAX_VISIBLE_UNDERLAY_NETWORKS = 4;
    private static final long RETRY_DELAY_MILLIS = 100;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        final String token = getIntent().getStringExtra(EXTRA_TOKEN);
        final String targetPackage = getIntent().getStringExtra(EXTRA_TARGET_PACKAGE);
        final InetAddress underlayTargetAddress = readUnderlayTargetAddress(getIntent());
        final int underlayTargetPort = getIntent().getIntExtra(EXTRA_UNDERLAY_TARGET_PORT, 0);
        if (!isValidToken(token) || !isExpectedTargetPackage(targetPackage)) {
            finish();
            return;
        }
        final Thread probe = new Thread(() -> {
            boolean tunneledTraffic = false;
            boolean bypassBlocked = false;
            boolean coverageGap = false;
            if (underlayTargetAddress != null && underlayTargetPort > 0 &&
                underlayTargetPort <= 65535) {
                try {
                    final ConnectivityManager connectivity =
                        getSystemService(ConnectivityManager.class);
                    if (connectivity == null) {
                        throw new IllegalStateException("CONNECTIVITY_SERVICE_UNAVAILABLE");
                    }
                    bypassBlocked = underlayConnectionIsBlockedForVisibleNetworks(
                        connectivity,
                        underlayTargetAddress,
                        underlayTargetPort
                    );
                } catch (Exception ignored) {
                    coverageGap = true;
                }
            } else {
                coverageGap = true;
            }
            try {
                tunneledTraffic = echoProbe() && dnsProbe();
            } catch (Exception ignored) {
                tunneledTraffic = false;
            }
            final Intent result = new Intent(ACTION_RESULT)
                .setPackage(targetPackage)
                .putExtra(EXTRA_TOKEN, token)
                .putExtra(EXTRA_SUCCESS, tunneledTraffic)
                .putExtra(EXTRA_BYPASS_BLOCKED, bypassBlocked)
                .putExtra(EXTRA_COVERAGE_GAP, coverageGap)
                .putExtra(EXTRA_PROBE_PACKAGE, getPackageName())
                .putExtra(EXTRA_PROBE_UID, Process.myUid());
            runOnUiThread(() -> {
                sendBroadcast(result);
                finish();
            });
        }, "vpn-probe");
        probe.setDaemon(true);
        probe.start();
    }

    private static boolean isValidToken(String token) {
        return token != null && token.matches("[0-9a-f]{32}");
    }

    private boolean isExpectedTargetPackage(String targetPackage) {
        final String probePackage = getPackageName();
        return probePackage.endsWith(".test") &&
            probePackage.substring(0, probePackage.length() - ".test".length())
                .equals(targetPackage);
    }

    private static InetAddress readUnderlayTargetAddress(Intent intent) {
        final byte[] encoded = intent.getByteArrayExtra(EXTRA_UNDERLAY_TARGET_ADDRESS);
        if (encoded == null || (encoded.length != 4 && encoded.length != 16)) {
            return null;
        }
        try {
            return InetAddress.getByAddress(encoded);
        } catch (IOException ignored) {
            return null;
        } finally {
            Arrays.fill(encoded, (byte) 0);
        }
    }

    @SuppressWarnings("deprecation")
    static boolean underlayConnectionIsBlockedForVisibleNetworks(
        ConnectivityManager connectivity,
        InetAddress targetAddress,
        int targetPort
    ) throws Exception {
        final Network[] visibleNetworks = connectivity.getAllNetworks();
        if (visibleNetworks == null) {
            throw new IllegalStateException("VISIBLE_NETWORKS_UNAVAILABLE");
        }
        int candidateCount = 0;
        for (Network candidateNetwork : visibleNetworks) {
            final NetworkCapabilities capabilities =
                connectivity.getNetworkCapabilities(candidateNetwork);
            if (capabilities == null ||
                capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN) ||
                !capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) {
                continue;
            }
            candidateCount++;
            if (candidateCount > MAX_VISIBLE_UNDERLAY_NETWORKS) {
                throw new IllegalStateException("VISIBLE_NETWORK_LIMIT_EXCEEDED");
            }
            if (!underlayConnectionIsBlocked(candidateNetwork, targetAddress, targetPort)) {
                return false;
            }
        }
        return true;
    }

    static boolean underlayConnectionIsBlocked(
        Network candidateNetwork,
        InetAddress targetAddress,
        int targetPort
    ) throws Exception {
        try (Socket socket = new Socket()) {
            try {
                candidateNetwork.bindSocket(socket);
                socket.connect(
                    new InetSocketAddress(targetAddress, targetPort),
                    UNDERLAY_ATTEMPT_TIMEOUT_MILLIS
                );
                return false;
            } catch (IOException | SecurityException expected) {
                return true;
            }
        }
    }

    private static boolean echoProbe() throws Exception {
        return retryUntilDeadline(VpnProbeActivity::echoAttempt);
    }

    private static boolean echoAttempt() throws Exception {
        final byte[] payload = new byte[] {0x4b, 0x56, 0x50, 0x4e};
        final byte[] replyBytes = new byte[32];
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setSoTimeout(ATTEMPT_TIMEOUT_MILLIS);
            socket.send(
                new DatagramPacket(
                    payload,
                    payload.length,
                    InetAddress.getByName("198.18.0.53"),
                    5353
                )
            );
            final DatagramPacket reply = new DatagramPacket(replyBytes, replyBytes.length);
            socket.receive(reply);
            return Arrays.equals(payload, Arrays.copyOf(reply.getData(), reply.getLength()));
        } finally {
            Arrays.fill(payload, (byte) 0);
            Arrays.fill(replyBytes, (byte) 0);
        }
    }

    private static boolean dnsProbe() throws Exception {
        return retryUntilDeadline(VpnProbeActivity::dnsAttempt);
    }

    private static boolean dnsAttempt() throws Exception {
        final byte[] query = new byte[] {
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x07, 'p', 'h', 'a', 's', 'e', '1', '0',
            0x04, 't', 'e', 's', 't',
            0x00, 0x00, 0x01, 0x00, 0x01
        };
        final byte[] replyBytes = new byte[512];
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setSoTimeout(ATTEMPT_TIMEOUT_MILLIS);
            socket.send(
                new DatagramPacket(
                    query,
                    query.length,
                    InetAddress.getByName("198.18.0.53"),
                    53
                )
            );
            final DatagramPacket reply = new DatagramPacket(replyBytes, replyBytes.length);
            socket.receive(reply);
            final int length = reply.getLength();
            return length == query.length + 16
                && (replyBytes[6] & 0xff) == 0
                && (replyBytes[7] & 0xff) == 1
                && (replyBytes[length - 4] & 0xff) == 198
                && (replyBytes[length - 3] & 0xff) == 18
                && (replyBytes[length - 2] & 0xff) == 0
                && (replyBytes[length - 1] & 0xff) == 42;
        } finally {
            Arrays.fill(query, (byte) 0);
            Arrays.fill(replyBytes, (byte) 0);
        }
    }

    private static boolean retryUntilDeadline(ProbeAttempt attempt) throws Exception {
        final long deadline = System.nanoTime() + PROBE_DEADLINE_NANOS;
        Exception lastFailure = null;
        do {
            try {
                if (attempt.run()) {
                    return true;
                }
            } catch (Exception failure) {
                lastFailure = failure;
            }
            if (System.nanoTime() >= deadline) {
                break;
            }
            Thread.sleep(RETRY_DELAY_MILLIS);
        } while (!Thread.currentThread().isInterrupted());
        if (Thread.currentThread().isInterrupted()) {
            throw new InterruptedException("VPN probe interrupted");
        }
        if (lastFailure != null) {
            throw lastFailure;
        }
        return false;
    }

    @FunctionalInterface
    private interface ProbeAttempt {
        boolean run() throws Exception;
    }
}
