// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package selfhost

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"math/big"
	"net"
	"testing"
	"time"

	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/runtimepolicy"
)

func TestLiveMaintenanceSignedPreviewSingleCategoryAndExpiry(t *testing.T) {
	o, _, next, now, dir := maintenanceFixtureFull(t)
	for _, category := range []int{-1, 1, 2, 3, 4, 5, 6, 7, 8, 9} {
		raw := maintenanceRewrite(t, o, next.Artifact, dir, func(p *envelope.CanonicalProfileV1, b *liveProfileBundleV2) {
			content, generation := p.ContentID, p.Generation
			*p = o.value
			p.Policy = bytes.Clone(o.value.Policy)
			p.ContentID = content
			p.Generation = generation
			p.UpdateKind = "replacement"
			p.PreviousContentID = o.value.ContentID
			b.Revocations = o.bundle.Revocations
			b.RevocationPayload = o.bundle.RevocationPayload
			b.RevocationSignature = o.bundle.RevocationSignature
			policy, err := runtimepolicy.DecodeRuntimeAt(p.Policy, now)
			if err != nil {
				t.Fatal(err)
			}
			switch category {
			case 1:
				policy.Endpoints[0].Port++
			case 2:
				policy.ClientIPv4[3]++
			case 3:
				// Routes are fixed default routes for each configured family.
				// A valid route change necessarily changes tunnel and DNS too.
				policy.ClientIPv6 = []byte{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
				policy.DNSIPv6 = []byte{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
				policy.Routes = append(policy.Routes, runtimepolicy.PrefixV2{Address: make([]byte, 16)})
				policy.DNSServers = append(policy.DNSServers, bytes.Clone(policy.DNSIPv6))
				policy.AllowedIPModes = []runtimepolicy.IPModeV2{runtimepolicy.IPModeDualStack}
			case 4:
				policy.DNSIPv4[3]++
				policy.DNSServers[0][3]++
			case 5:
				p.StrategyIDs = []string{"different"}
			case 6:
				key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, 32))
				cert := &x509.Certificate{SerialNumber: big.NewInt(78), DNSNames: []string{policy.TLSServerName}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(30 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
				if ip := net.ParseIP(policy.TLSServerName); ip != nil {
					cert.DNSNames = nil
					cert.IPAddresses = []net.IP{ip}
				}
				policy.TLSLeafDER, err = x509.CreateCertificate(rand.Reader, cert, cert, key.Public(), key)
				if err != nil {
					t.Fatal(err)
				}
				policy.TLSLeafSHA256 = sha256.Sum256(policy.TLSLeafDER)
			case 7:
				policy.Limits.MaxIdleSeconds--
			case 8:
				policy.Services.Update.MinCheckIntervalSeconds++
			case 9:
				p.ValidUntil--
			}
			policy.RelayAdmissionDigest, err = runtimepolicy.RelayAdmissionDigestRuntimeAt(policy, now)
			if err != nil {
				t.Fatalf("category %d fixture: %v", category, err)
			}
			p.Policy, err = runtimepolicy.EncodeRuntimeAt(policy, now)
			if err != nil {
				t.Fatal(err)
			}
		})
		c, _, err := o.VerifyCandidateAt(raw, now)
		if err != nil {
			t.Fatalf("category %d candidate: %v", category, err)
		}
		preview, _ := c.PreviewV1()
		var want [10]uint8
		if category >= 0 {
			want[category] = 1
		}
		if category == 3 {
			want[2], want[4] = 1, 1
		}
		if preview.ChangedCategories != want {
			t.Fatalf("category %d: %v want %v", category, preview.ChangedCategories, want)
		}
		wantFlags := uint8(0)
		if category == 6 {
			wantFlags = 4
		}
		if preview.RotationFlags != wantFlags {
			t.Fatal("unexpected rotation flag")
		}
		c.Destroy()
	}
	for _, seconds := range []int64{604800, 604801} {
		raw := maintenanceRewrite(t, o, next.Artifact, dir, func(p *envelope.CanonicalProfileV1, _ *liveProfileBundleV2) { p.ValidUntil = now.Unix() + seconds })
		c, _, err := o.VerifyCandidateAt(raw, now)
		if err != nil {
			t.Fatal(err)
		}
		v, _ := c.PreviewV1()
		want := uint8(1)
		if seconds > 604800 {
			want = 0
		}
		if v.ExpiryCategory != want {
			t.Fatal("expiry boundary changed")
		}
		if err := o.RevalidateCandidateAt(c, now.Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		v, _ = c.PreviewV1()
		if v.ExpiryCategory != 1 {
			t.Fatal("fresh expiry cache not recomputed")
		}
		c.Destroy()
		// Advance consistently for the next sequential owner operation.
		now = now.Add(time.Second)
	}
}
