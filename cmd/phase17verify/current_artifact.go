// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"bytes"
	"debug/elf"
	"fmt"
	"strings"
)

// Current packages contain the production facade and a legitimate trust-failure
// status. The historical predecessor policy remains separately regression-tested.
var currentRequiredAPKMarkers = append(append([]string(nil), phase17RequiredAPKMarkers...), "nativeProdOpenV1", "nativeMaintenanceOpenV1")
var currentForbiddenAPKMarkers = append(withoutNativeNames(phase17ForbiddenAPKMarkers, "TRUST_UNAVAILABLE"),
	"InternalConformanceBridge", "Task7InstalledFixtureNative", "Task7MaintenanceFixtureNative", "AndroidPlatformConformanceV1")

func withoutNativeNames(names []string, excluded ...string) []string {
	var result []string
	for _, name := range names {
		keep := true
		for _, omit := range excluded {
			if name == omit {
				keep = false
			}
		}
		if keep {
			result = append(result, name)
		}
	}
	return result
}

// Closed, reviewed interfaces, never inferred from the APK being checked. The
// Go DSO owns backing operations; the JNI DSO exports only its canonical facade
// and Java entries. Test controls are admitted solely in the internal variant.
func currentNativeSymbols(internal bool) (bridge, jni []string) {
	bridge = withoutNativeNames(phase17BridgeSymbols, "kvpn_phase11_roundtrip", "kvpn_runtime_session_roundtrip")
	bridge = append(bridge, strings.Fields(`
kvpn_android_call_cancelled_v1 kvpn_android_call_remaining_millis_v1 kvpn_android_maintenance_network_lost_v1
kvpn_android_revision_invalidated_v1 kvpn_android_socket_lost_v1 kvpn_android_table_valid_v1
kvpn_bootstrap_legacy_binding_v1 kvpn_bootstrap_production_binding_v1
kvpn_go_android_platform_finalize_v1 kvpn_go_discard_maintenance_candidate_v1 kvpn_go_discard_maintenance_parent_v1
kvpn_go_discard_prod_packet_v1 kvpn_go_discard_prod_parent_v1 kvpn_go_discard_prod_stream_v1 kvpn_go_discard_stream_delivery_v1
kvpn_go_maintenance_cancel_v1 kvpn_go_maintenance_check_update_v1 kvpn_go_maintenance_close_v1 kvpn_go_maintenance_materialize_v1
kvpn_go_maintenance_open_v1 kvpn_go_maintenance_release_update_v1 kvpn_go_maintenance_retired_result_v1
kvpn_go_maintenance_retirement_publish_v1 kvpn_go_maintenance_run_probe_v1 kvpn_go_output_overlap_backing_v1
kvpn_go_prod_cancel_v1 kvpn_go_prod_close_v1 kvpn_go_prod_confirm_packet_v1 kvpn_go_prod_confirm_socket_v1 kvpn_go_prod_handover_v1
kvpn_go_prod_next_control_v1 kvpn_go_prod_open_stream_v1 kvpn_go_prod_open_v1 kvpn_go_prod_receive_packet_v1 kvpn_go_prod_reconnect_v1
kvpn_go_prod_reject_packet_v1 kvpn_go_prod_retired_result_v1 kvpn_go_prod_retirement_publish_v1 kvpn_go_prod_run_probe_v1
kvpn_go_prod_submit_packet_v1 kvpn_go_stream_cancel_v1 kvpn_go_stream_close_v1 kvpn_go_stream_confirm_v1
kvpn_go_stream_half_close_v1 kvpn_go_stream_receive_v1 kvpn_go_stream_reject_v1 kvpn_go_stream_send_v1`)...)
	const prefix = "Java_org_kurdistanvpn_core_nativejni_"
	jni = withoutNativeNames(phase17JNISymbols, prefix+"NativeBridge_nativePhase11RoundTrip", prefix+"NativeBridge_nativeRuntimeSessionRoundTrip")
	jni = append(jni, "Java_org_kurdistanvpn_runtime_android_RuntimeTunProofOwner_readTunIdentity", "Java_org_kurdistanvpn_runtime_android_AndroidTunPacketEndpoint_prepareNonblocking")
	for _, method := range strings.Fields(`
nativeBootstrapLegacyBindingV1 nativeBootstrapProductionBindingV1
nativeMaintenanceCancelV1 nativeMaintenanceCheckUpdateV1 nativeMaintenanceCloseV1 nativeMaintenanceMaterializeV1 nativeMaintenanceOpenV1
nativeMaintenanceReleaseUpdateV1 nativeMaintenanceRunProbeV1 nativeProdCancelV1 nativeProdCloseV1 nativeProdConfirmPacketV1
nativeProdConfirmSocketV1 nativeProdHandoverV1 nativeProdNextControlV1 nativeProdOpenStreamV1 nativeProdOpenV1 nativeProdReceivePacketV1
nativeProdReconnectV1 nativeProdRejectPacketV1 nativeProdRunProbeV1 nativeProdSubmitPacketV1 nativeStreamCancelV1 nativeStreamCloseV1
nativeStreamConfirmV1 nativeStreamHalfCloseV1 nativeStreamReceiveV1 nativeStreamRejectV1 nativeStreamSendV1`) {
		jni = append(jni, prefix+"NativeBridge_"+method)
	}
	for _, method := range strings.Fields(`abandonUnclaimed callCancelled callRemainingMillis finalizeFailedOpening maintenanceNetworkLost registerOwned revisionFence revisionInvalidated socketLost`) {
		jni = append(jni, prefix+"AndroidProductionCallbacks_"+method)
	}
	jni = append(jni, strings.Fields(`
kvpn_maintenance_cancel_v1 kvpn_maintenance_check_update_v1 kvpn_maintenance_close_v1
kvpn_maintenance_materialize_v1 kvpn_maintenance_open_v1 kvpn_maintenance_release_update_v1 kvpn_maintenance_run_probe_v1
kvpn_prod_cancel_v1 kvpn_prod_close_v1 kvpn_prod_confirm_packet_v1 kvpn_prod_confirm_socket_v1 kvpn_prod_handover_v1
kvpn_prod_next_control_v1 kvpn_prod_open_stream_v1 kvpn_prod_open_v1 kvpn_prod_receive_packet_v1 kvpn_prod_reconnect_v1
kvpn_prod_reject_packet_v1 kvpn_prod_run_probe_v1 kvpn_prod_submit_packet_v1
kvpn_stream_cancel_v1 kvpn_stream_close_v1 kvpn_stream_confirm_v1 kvpn_stream_half_close_v1
kvpn_stream_receive_v1 kvpn_stream_reject_v1 kvpn_stream_send_v1`)...)
	if internal {
		bridge = append(bridge, strings.Fields(`kvpn_phase11_roundtrip kvpn_runtime_session_roundtrip kvpn_task7_cancel_v1 kvpn_task7_finish_v1 kvpn_task7_issue_v1 kvpn_task7_snapshot_v1 kvpn_task7_start_v1 kvpn_task7_maintenance_run_v1`)...)
		for _, name := range strings.Fields(`AndroidPlatformConformanceV1_nativeCopyCapture AndroidPlatformConformanceV1_nativeCopyLayout AndroidPlatformConformanceV1_nativeRejectUnownedCancellation
InternalConformanceBridge_nativePhase11RoundTrip InternalConformanceBridge_nativeRuntimeSessionRoundTrip
Task7InstalledFixtureNative_nativeCancel Task7InstalledFixtureNative_nativeFinish Task7InstalledFixtureNative_nativeIssue Task7InstalledFixtureNative_nativeSnapshot Task7InstalledFixtureNative_nativeStart Task7MaintenanceFixtureNative_nativeRun`) {
			jni = append(jni, prefix+name)
		}
	}
	return bridge, jni
}

func requireCurrentSymbols(data []byte, expected []string) error {
	file, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer file.Close()
	symbols, err := file.DynamicSymbols()
	if err != nil {
		return err
	}
	return verifyCurrentNativeExports(symbols, expected)
}

func verifyCurrentNativeExports(symbols []elf.Symbol, expected []string) error {
	var actual []string
	for _, symbol := range symbols {
		if symbol.Section == elf.SHN_UNDEF || !(strings.HasPrefix(symbol.Name, "kvpn_") || strings.HasPrefix(symbol.Name, "Java_") || strings.HasPrefix(symbol.Name, "JNI_")) {
			continue
		}
		// VER_NDX_GLOBAL (1) means an ordinary unversioned global, even when
		// the ELF contains a version table for its imported system symbols.
		versioned := symbol.HasVersion && (symbol.VersionIndex.Index() != 1 || symbol.VersionIndex.IsHidden())
		if elf.ST_TYPE(symbol.Info) != elf.STT_FUNC || elf.ST_BIND(symbol.Info) != elf.STB_GLOBAL || symbol.Other != byte(elf.STV_DEFAULT) || versioned {
			return fmt.Errorf("native export is not an unversioned globally visible function: %q", symbol.Name)
		}
		actual = append(actual, symbol.Name)
	}
	return comparePhase17Symbols(actual, expected)
}
