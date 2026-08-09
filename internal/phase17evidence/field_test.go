// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package phase17evidence

import (
	"bytes"
	"testing"
)

func TestConvertOwnedVPSMarksOnlyProvenLocalEvidence(t *testing.T) {
	current := Acceptance{
		Schema: AcceptanceSchema, Phase: 17, Status: "IN_PROGRESS",
		Local: map[string]string{
			"api26Emulator": "PENDING", "api34Emulator": "PENDING", "api36Emulator": "PENDING",
			"currentArtifactPolicy": "PASS", "historicalSupersession": "PASS", "linuxNamespace": "PASS",
			"loadRecoveryPrivacyCampaign": "PENDING", "ownedVps": "PENDING",
		},
		External: map[string]string{
			"physicalApi26Device": "UNVERIFIED", "physicalApi34Device": "UNVERIFIED", "secondVpsProvider": "UNVERIFIED",
		},
		Limitations: []string{"first-provider field evidence pending", "external evidence pending"},
	}
	updated, err := ConvertOwnedVPS(validOwnedVPSEvidence(t), current)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Local["ownedVps"] != "PASS" || updated.Local["api36Emulator"] != "PASS" {
		t.Fatalf("owned VPS/API36 evidence not promoted: %+v", updated.Local)
	}
	if updated.Local["api26Emulator"] != "PENDING" || updated.Local["api34Emulator"] != "PENDING" || updated.Local["loadRecoveryPrivacyCampaign"] != "PENDING" {
		t.Fatalf("unproven evidence widened: %+v", updated.Local)
	}
	if updated.Complete || updated.Status != "IN_PROGRESS" || len(updated.Limitations) == 0 {
		t.Fatalf("external blockers hidden: %+v", updated)
	}
}

func TestOwnedVPSEvidenceRejectsMissingProofAndSensitiveMaterial(t *testing.T) {
	valid := validOwnedVPSEvidence(t)
	missing := bytes.Replace(valid, []byte(`"revocation":"PASS",`), nil, 1)
	if _, err := DecodeOwnedVPS(missing); err == nil {
		t.Fatal("missing proof was accepted")
	}
	leaked := bytes.Replace(valid, []byte(`"hostClass":"OWNER_CONTROLLED_VPS"`), []byte(`"hostClass":"198.51.100.7"`), 1)
	if _, err := DecodeOwnedVPS(leaked); err == nil {
		t.Fatal("owner endpoint was accepted")
	}
	ipv6Leaked := bytes.Replace(valid, []byte(`"hostClass":"OWNER_CONTROLLED_VPS"`), []byte(`"hostClass":"2001:db8::7"`), 1)
	if _, err := DecodeOwnedVPS(ipv6Leaked); err == nil {
		t.Fatal("owner IPv6 endpoint was accepted")
	}
}

func TestOwnedVPSEvidenceRejectsAddressLiteralsInsideEndpointsAndURLs(t *testing.T) {
	for _, leaked := range []string{
		`endpoint=192.0.2.10:443`,
		`probe=https://198.51.100.20/check`,
		`endpoint=[2001:db8::10]:443`,
		`interface=fe80::1%eth0`,
	} {
		if !containsSensitiveFieldEvidence([]byte(leaked)) {
			t.Fatalf("sensitive endpoint accepted: %s", leaked)
		}
	}
}

func TestOwnedVPSEvidenceRejectsIncompleteStressInventory(t *testing.T) {
	valid := validOwnedVPSEvidence(t)
	stress := bytes.Replace(valid,
		[]byte(`"mode":"Functional","restartReconnectCycles":0,"profileRotationCycles":0,"impairments":[],"soakDurationMs":0,"soakCycles":0`),
		[]byte(`"mode":"Stress","restartReconnectCycles":99,"profileRotationCycles":100,"impairments":["bandwidth","latency","loss","combined","carrier-reset"],"soakDurationMs":0,"soakCycles":0`), 1)
	if _, err := DecodeOwnedVPS(stress); err == nil {
		t.Fatal("incomplete stress inventory was accepted")
	}
}

func TestConvertOwnedVPSSoakPromotesCompletedLoadRecoveryPrivacyCampaign(t *testing.T) {
	current := Acceptance{
		Schema: AcceptanceSchema, Phase: 17, Status: "IN_PROGRESS",
		Local: map[string]string{
			"api26Emulator": "PASS", "api34Emulator": "PASS", "api36Emulator": "PASS",
			"currentArtifactPolicy": "PASS", "historicalSupersession": "PASS", "linuxNamespace": "PASS",
			"loadRecoveryPrivacyCampaign": "PENDING", "ownedVps": "PASS",
		},
		External: map[string]string{
			"physicalApi26Device": "UNVERIFIED", "physicalApi34Device": "UNVERIFIED", "secondVpsProvider": "UNVERIFIED",
		},
		Limitations: []string{"external evidence pending"},
	}
	soak := bytes.Replace(validOwnedVPSEvidence(t),
		[]byte(`"mode":"Functional","restartReconnectCycles":0,"profileRotationCycles":0,"impairments":[],"soakDurationMs":0,"soakCycles":0`),
		[]byte(`"mode":"Soak12h","restartReconnectCycles":100,"profileRotationCycles":100,"impairments":["bandwidth","latency","loss","combined","carrier-reset"],"soakDurationMs":43200000,"soakCycles":2`), 1)
	updated, err := ConvertOwnedVPS(soak, current)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Local["loadRecoveryPrivacyCampaign"] != "PASS" {
		t.Fatalf("soak campaign not promoted: %+v", updated.Local)
	}
	if len(updated.Limitations) != 1 || updated.Limitations[0] != "physical Android devices and a second unrelated VPS provider remain external evidence" {
		t.Fatalf("stale local limitation retained: %+v", updated.Limitations)
	}
}

func validOwnedVPSEvidence(t *testing.T) []byte {
	t.Helper()
	checks := ""
	for index, name := range RequiredOwnedVPSChecks() {
		if index != 0 {
			checks += ","
		}
		checks += `"` + name + `":"PASS"`
	}
	return []byte(`{"schema":"kurdistan-phase17-owned-vps-evidence-v2","result":"PASS","subject":{"commitSha":"0123456789abcdef0123456789abcdef01234567","treeSha":"89abcdef0123456789abcdef0123456789abcdef","packageSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","appApkSha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","testApkSha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},"environment":{"hostClass":"OWNER_CONTROLLED_VPS","os":"linux","arch":"amd64","androidClass":"EMULATOR","androidApi":36,"androidAbi":"x86_64","ipv4":true,"ipv6":true},"checks":{` + checks + `},"metrics":{"durationMs":1200,"peakRssBytes":1048576,"peakFileDescriptors":12,"reconnects":2},"privacy":{"payloadRetained":false,"destinationRetained":false,"dnsNameRetained":false,"credentialRetained":false,"keyRetained":false,"profileRetained":false,"rawLogRetained":false},"limitations":["first owner-controlled provider and emulator evidence only"],"campaign":{"mode":"Functional","restartReconnectCycles":0,"profileRotationCycles":0,"impairments":[],"soakDurationMs":0,"soakCycles":0}}`)
}
