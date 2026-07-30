// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.app;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;

public final class VpnProbeActivity extends Activity {
    public static final String ACTION_RESULT = "org.kurdistanvpn.test.VPN_PROBE_RESULT";
    public static final String EXTRA_TOKEN = "token";
    public static final String EXTRA_SUCCESS = "success";
    public static final String EXTRA_TARGET_PACKAGE = "target-package";
    private static final long PROBE_DEADLINE_NANOS = TimeUnit.SECONDS.toNanos(5);
    private static final int ATTEMPT_TIMEOUT_MILLIS = 750;
    private static final long RETRY_DELAY_MILLIS = 100;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        final String token = getIntent().getStringExtra(EXTRA_TOKEN);
        final String targetPackage = getIntent().getStringExtra(EXTRA_TARGET_PACKAGE);
        if (token == null || targetPackage == null || targetPackage.isBlank()) {
            finish();
            return;
        }
        final Thread probe = new Thread(() -> {
            boolean success = false;
            try {
                success = echoProbe() && dnsProbe();
            } catch (Exception ignored) {
                success = false;
            }
            sendBroadcast(
                new Intent(ACTION_RESULT)
                    .setPackage(targetPackage)
                    .putExtra(EXTRA_TOKEN, token)
                    .putExtra(EXTRA_SUCCESS, success)
            );
            runOnUiThread(this::finish);
        }, "vpn-probe");
        probe.setDaemon(true);
        probe.start();
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
