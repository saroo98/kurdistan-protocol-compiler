// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package auth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"sort"
	"strings"
	"testing"

	"kurdistan/internal/crypto/security"
	"kurdistan/internal/protocol/compiler"
	"kurdistan/internal/protocol/ir"
)

type memoryIdentity struct {
	id  string
	key ed25519.PrivateKey
}

type trackingIdentity struct {
	id          string
	key         ed25519.PrivateKey
	transferred ed25519.PrivateKey
}

func (p *trackingIdentity) Local(id string) (ed25519.PrivateKey, error) {
	if id != p.id {
		return nil, errors.New("unknown")
	}
	p.transferred = append(ed25519.PrivateKey(nil), p.key...)
	return p.transferred, nil
}

func (p memoryIdentity) Local(id string) (ed25519.PrivateKey, error) {
	if id != p.id {
		return nil, errors.New("unknown")
	}
	return append(ed25519.PrivateKey(nil), p.key...), nil
}

type memoryTrust struct {
	id  string
	key ed25519.PublicKey
}

func (p memoryTrust) Peer(id string) (ed25519.PublicKey, error) {
	if id != p.id {
		return nil, errors.New("unknown")
	}
	return append(ed25519.PublicKey(nil), p.key...), nil
}

type firstContactFixture struct {
	input                        FirstContactInput
	profile                      *ir.Profile
	clientPrivate, serverPrivate ed25519.PrivateKey
	clientPublic, serverPublic   ed25519.PublicKey
}

func newFirstContactFixture(t *testing.T, mode string) firstContactFixture {
	t.Helper()
	p, err := compiler.Generate(6100 + int64(len(mode)))
	if err != nil {
		t.Fatal(err)
	}
	p.Security.TranscriptMode = mode
	p.Security.CapabilityNegotiationPolicy = "intersection_with_required"
	p.Security.DowngradePolicy = "strict_capabilities"
	p.GenerationHash = ""
	p.GenerationHash, err = ir.CanonicalHash(p)
	if err != nil {
		t.Fatal(err)
	}
	known := ir.SecurityCapabilities()
	floor := append([]string(nil), known[:1]...)
	selected := append([]string(nil), known[:3]...)
	policy, err := ir.BuildEffectiveSecurityPolicy(p, floor, floor, selected)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewPeerParameters("client-test", p, policy, policy, selected, floor)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewPeerParameters("server-test", p, policy, policy, selected, floor)
	if err != nil {
		t.Fatal(err)
	}
	clientPublic, clientPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverPublic, serverPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := NewHandshakeReplayCache(65536)
	if err != nil {
		t.Fatal(err)
	}
	fixture := firstContactFixture{
		profile:       p,
		clientPrivate: clientPrivate, serverPrivate: serverPrivate,
		clientPublic: clientPublic, serverPublic: serverPublic,
	}
	fixture.input = FirstContactInput{
		Client: client, Server: server, SelectedPolicy: policy, SelectedCapabilities: selected,
		ClientDependencies: Dependencies{Identity: memoryIdentity{"client-test", clientPrivate}, Trust: memoryTrust{"server-test", serverPublic}},
		ServerDependencies: Dependencies{Identity: memoryIdentity{"server-test", serverPrivate}, Trust: memoryTrust{"client-test", clientPublic}},
		Replay:             replay,
	}
	t.Cleanup(func() { wipe(clientPrivate); wipe(serverPrivate) })
	return fixture
}

func TestAuthenticatedFirstContactFreshSessionNonceReplayAndKeys(t *testing.T) {
	fixture := newFirstContactFixture(t, security.TranscriptCanonicalV1)
	first, err := FirstContact(fixture.input)
	if err != nil {
		t.Fatal(err)
	}
	second, err := FirstContact(fixture.input)
	if err != nil {
		t.Fatal(err)
	}
	if first.ClientState != StateEstablished || first.ServerState != StateAuthenticating {
		t.Fatalf("unexpected explicit end states: %s/%s", first.ClientState, first.ServerState)
	}
	if first.ClientNonce == second.ClientNonce || first.ServerNonce == second.ServerNonce {
		t.Fatal("two sessions reused a fresh nonce")
	}
	if first.ClientPublic == second.ClientPublic || first.ServerPublic == second.ServerPublic || first.ClientPublic == first.ServerPublic || second.ClientPublic == second.ServerPublic {
		t.Fatal("two sessions reused or cross-shared an X25519 public contribution")
	}
	if bytes.Equal(first.ChannelSecret, second.ChannelSecret) || first.TranscriptHash == second.TranscriptHash {
		t.Fatal("two sessions reused channel key material or transcript identity")
	}
	_, err = firstContact(fixture.input, func(point mutationPoint, message []byte) []byte {
		if point == mutateClientHello {
			return append([]byte(nil), first.Messages[0]...)
		}
		return message
	})
	assertHandshakeCode(t, err, FailureReplay)
}

func TestDirectWireVersionUnsupportedVersion(t *testing.T) {
	source := newFirstContactFixture(t, security.TranscriptCanonicalV1)
	first, err := FirstContact(source.input)
	if err != nil {
		t.Fatal(err)
	}
	wire := append([]byte(nil), first.Messages[0]...)
	if len(wire) < 6 {
		t.Fatal("short client hello")
	}
	wire[5] ^= 1
	fixture := newFirstContactFixture(t, security.TranscriptCanonicalV1)
	fixture.input.InboundClientHello = wire
	result, err := FirstContact(fixture.input)
	assertClosedHandshakeCode(t, result, err, FailureUnsupportedVersion)
	var typed *HandshakeError
	if !errors.As(err, &typed) || typed.Code != FailureUnsupportedVersion || err.Error() != "authenticated first contact failed: unsupported_version" {
		t.Fatalf("direct wire category err=%v typed=%+v", err, typed)
	}
	for _, operand := range []string{"version=2", "0x0002", string(wire)} {
		if strings.Contains(err.Error(), operand) {
			t.Fatalf("wire diagnostic leaked operand %q", operand)
		}
	}
	for _, cause := range []error{ir.ErrProfileMalformed, ir.ErrProfileVersionUnsupported, ir.ErrProfileVersionMismatch, ir.ErrMigrationRequired, ir.ErrProfileInvalid, ir.ErrProfileMismatch} {
		if errors.Is(err, cause) {
			t.Fatalf("auth wire error exposed IR cause %v", cause)
		}
	}
}

func TestDirectWireVersionNoRawProfileOrMigrationReachability(t *testing.T) {
	raw, err := os.ReadFile("handshake.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, forbidden := range []string{"DecodeProfileV1", "DecodeLegacyProfileForMigrationV1", "internal/crypto/profilemigration"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("auth production reaches %s", forbidden)
		}
	}
}

func TestHandshakeOneSidedTranscriptDerivationSubstitutionFailsConfirmation(t *testing.T) {
	fixture := newFirstContactFixture(t, security.TranscriptFullBindingV1)
	_, err := firstContactWithOptions(fixture.input, executionOptions{
		mutateClientTH2: func(transcript *[32]byte) { transcript[0] ^= 1 },
	})
	assertHandshakeCode(t, err, FailureKeyConfirmation)
}

func TestHandshakeReplayCacheFailsClosedAtBound(t *testing.T) {
	fixture := newFirstContactFixture(t, security.TranscriptCanonicalV1)
	cache, err := NewHandshakeReplayCache(1)
	if err != nil {
		t.Fatal(err)
	}
	fixture.input.Replay = cache
	first, err := FirstContact(fixture.input)
	if err != nil {
		t.Fatal(err)
	}
	_, err = FirstContact(fixture.input)
	assertHandshakeCode(t, err, FailureInternalLimit)
	replayed := fixture.input
	replayed.InboundClientHello = append([]byte(nil), first.Messages[0]...)
	_, err = FirstContact(replayed)
	assertHandshakeCode(t, err, FailureReplay)
}

func TestHandshakeReplayCommitsAfterTrustBeforeSemanticValidation(t *testing.T) {
	for _, tt := range []struct {
		name string
		kind string
		want FailureCode
	}{
		{name: "profile mismatch", kind: "profile", want: FailureProfileMismatch},
		{name: "policy mismatch", kind: "policy", want: FailurePolicyMismatch},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fixture := newFirstContactFixture(t, security.TranscriptCanonicalV1)
			trustedSigned := trustedSignedMismatchedClientHello(t, fixture, tt.kind)

			untrusted := append([]byte(nil), trustedSigned...)
			untrusted[len(untrusted)-1] ^= 1
			input := fixture.input
			input.InboundClientHello = untrusted
			result, err := FirstContact(input)
			assertClosedHandshakeCode(t, result, err, FailureSignatureInvalid)

			input.InboundClientHello = trustedSigned
			result, err = FirstContact(input)
			assertClosedHandshakeCode(t, result, err, tt.want)
			result, err = FirstContact(input)
			assertClosedHandshakeCode(t, result, err, FailureReplay)
		})
	}
}

func trustedSignedMismatchedClientHello(t *testing.T, fixture firstContactFixture, kind string) []byte {
	t.Helper()
	var public, nonce [32]byte
	public[0], nonce[0] = 1, 2
	wire, _, err := makeClientHello(fixture.input.Client, fixture.clientPrivate, public, nonce)
	if err != nil {
		t.Fatal(err)
	}
	body, err := decodeOuter(wire)
	if err != nil {
		t.Fatal(err)
	}
	unsigned := append([]byte(nil), body[:len(body)-ed25519.SignatureSize]...)
	var field []byte
	switch kind {
	case "profile":
		field = fixture.input.Client.ProfileHash[:]
	case "policy":
		field, err = encodePolicyOffer(fixture.input.Client.OfferPolicy, fixture.input.Client.OfferedCapabilities)
		if err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatal("unknown mismatch kind")
	}
	index := bytes.Index(unsigned, field)
	if index < 0 {
		t.Fatal("signed mismatch target not found")
	}
	unsigned[index+len(field)-1] ^= 1
	signatureHash := protocolHash("kurdistan/handshake/v1/client-hello-signature", unsigned)
	signed := append(unsigned, ed25519.Sign(fixture.clientPrivate, signatureHash[:])...)
	return encodeOuter(signed)
}

func TestHandshakeCapturedCompleteExchangeCannotEstablishWithNewReplayContext(t *testing.T) {
	fixture := newFirstContactFixture(t, security.TranscriptFullBindingV1)
	first, err := FirstContact(fixture.input)
	if err != nil {
		t.Fatal(err)
	}
	newReplay, err := NewHandshakeReplayCache(65536)
	if err != nil {
		t.Fatal(err)
	}
	fixture.input.Replay = newReplay
	result, err := firstContactWithOptions(fixture.input, executionOptions{replayMessages: &first.Messages})
	assertClosedHandshakeCode(t, result, err, FailureProfileMismatch)
}

func TestHandshakeTimeoutReservedAndUnreachableInSynchronousCandidate(t *testing.T) {
	fixture := newFirstContactFixture(t, security.TranscriptCanonicalV1)
	result, err := firstContactWithOptions(fixture.input, executionOptions{clientEntropy: errorReader{}})
	var typed *HandshakeError
	if !errors.As(err, &typed) {
		t.Fatalf("expected typed terminal failure, got %v", err)
	}
	if typed.Code == FailureTimeout {
		t.Fatal("synchronous local failure incorrectly reported reserved handshake_timeout")
	}
	assertClosedHandshakeCode(t, result, err, FailureEntropy)
}

func TestHandshakeCredentialSourcesAreFreshAndUnsafeMaterialIsRejected(t *testing.T) {
	seenCredentials := map[[32]byte]bool{}
	for _, name := range []string{"alpha", "beta", "gamma"} {
		t.Run(name, func(t *testing.T) {
			fixture := newFirstContactFixture(t, security.TranscriptCanonicalV1)
			clientFingerprint := sha256.Sum256(fixture.clientPrivate)
			serverFingerprint := sha256.Sum256(fixture.serverPrivate)
			if clientFingerprint == serverFingerprint || seenCredentials[clientFingerprint] || seenCredentials[serverFingerprint] {
				t.Fatal("client or server credential bytes reused across test cases")
			}
			seenCredentials[clientFingerprint] = true
			seenCredentials[serverFingerprint] = true
			if _, err := FirstContact(fixture.input); err != nil {
				t.Fatal(err)
			}
		})
	}

	t.Run("missing provider", func(t *testing.T) {
		fixture := newFirstContactFixture(t, security.TranscriptCanonicalV1)
		fixture.input.ClientDependencies.Identity = nil
		result, err := FirstContact(fixture.input)
		assertClosedHandshakeCode(t, result, err, FailureUnknownIdentity)
	})
	t.Run("public-derived private material", func(t *testing.T) {
		fixture := newFirstContactFixture(t, security.TranscriptCanonicalV1)
		fixture.input.ClientDependencies.Identity = memoryIdentity{"client-test", ed25519.PrivateKey(fixture.clientPublic)}
		result, err := FirstContact(fixture.input)
		assertClosedHandshakeCode(t, result, err, FailureUntrustedIdentity)
	})
	t.Run("default zero material", func(t *testing.T) {
		fixture := newFirstContactFixture(t, security.TranscriptCanonicalV1)
		fixture.input.ClientDependencies.Identity = memoryIdentity{"client-test", make(ed25519.PrivateKey, ed25519.PrivateKeySize)}
		result, err := FirstContact(fixture.input)
		assertClosedHandshakeCode(t, result, err, FailureUntrustedIdentity)
	})
	t.Run("entropy failure", func(t *testing.T) {
		fixture := newFirstContactFixture(t, security.TranscriptCanonicalV1)
		result, err := firstContactWithOptions(fixture.input, executionOptions{clientEntropy: errorReader{}})
		assertClosedHandshakeCode(t, result, err, FailureEntropy)
	})
}

func TestHandshakeWipesBothProviderTransferredCredentialCopies(t *testing.T) {
	fixture := newFirstContactFixture(t, security.TranscriptCanonicalV1)
	client := &trackingIdentity{id: "client-test", key: fixture.clientPrivate}
	server := &trackingIdentity{id: "server-test", key: fixture.serverPrivate}
	fixture.input.ClientDependencies.Identity = client
	fixture.input.ServerDependencies.Identity = server
	if _, err := FirstContact(fixture.input); err != nil {
		t.Fatal(err)
	}
	for role, transferred := range map[string]ed25519.PrivateKey{"client": client.transferred, "server": server.transferred} {
		if len(transferred) != ed25519.PrivateKeySize {
			t.Fatalf("%s provider did not transfer a private-key copy", role)
		}
		for _, value := range transferred {
			if value != 0 {
				t.Fatalf("%s provider-returned private-key copy was not wiped", role)
			}
		}
	}
}

func TestHandshakeWipesBothInternalPrivateKeyCopies(t *testing.T) {
	fixture := newFirstContactFixture(t, security.TranscriptCanonicalV1)
	var clientCopy, serverCopy ed25519.PrivateKey
	if _, err := firstContactWithOptions(fixture.input, executionOptions{
		observePrivateCopies: func(client, server ed25519.PrivateKey) {
			clientCopy, serverCopy = client, server
		},
	}); err != nil {
		t.Fatal(err)
	}
	for role, internal := range map[string]ed25519.PrivateKey{"client": clientCopy, "server": serverCopy} {
		if len(internal) != ed25519.PrivateKeySize {
			t.Fatalf("%s internal private-key copy was not observed", role)
		}
		for _, value := range internal {
			if value != 0 {
				t.Fatalf("%s internal private-key copy was not wiped", role)
			}
		}
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestHandshakeFourTranscriptModesExactOrderedVectorsAndTamper(t *testing.T) {
	modes := []struct{ mode, id string }{
		{security.TranscriptCanonicalV1, "pm-owner:transcript/canonical_v1"},
		{security.TranscriptCapabilitiesV1, "pm-owner:transcript/canonical_with_capabilities_v1"},
		{security.TranscriptCarrierBindingV1, "pm-owner:transcript/canonical_with_carrier_binding_v1"},
		{security.TranscriptFullBindingV1, "pm-owner:transcript/canonical_full_binding_v1"},
	}
	for _, item := range modes {
		mode, id := item.mode, item.id
		t.Run(id, func(t *testing.T) {
			fixture := newFirstContactFixture(t, mode)
			clientBinding := fixture.input.Client.modeBinding
			clientBinding.ClientOptional = optionalCapabilities(fixture.input.Client.OfferedCapabilities, fixture.input.Client.RequiredCapabilities)
			clientBinding.ServerOptional = optionalCapabilities(fixture.input.Server.OfferedCapabilities, fixture.input.Server.RequiredCapabilities)
			got, err := security.CanonicalHandshakeModeBinding(mode, clientBinding)
			if err != nil {
				t.Fatal(err)
			}
			want := exactModeVector(t, mode, clientBinding)
			if !bytes.Equal(got, want) {
				t.Fatalf("%s mode vector order mismatch\n got %x\nwant %x", id, got, want)
			}
			if _, err := FirstContact(fixture.input); err != nil {
				t.Fatal(err)
			}

		})
	}
	for _, id := range []string{"pm-owner:suite/aead_aes_256_gcm", "pm-owner:suite/mac_hmac_sha256"} {
		t.Run(id, func(t *testing.T) {
			fixture := newFirstContactFixture(t, security.TranscriptCanonicalV1)
			if _, err := FirstContact(fixture.input); err != nil {
				t.Fatalf("%s: %v", id, err)
			}
		})
	}
}

func TestHandshakeOptionalCapabilitySourceAddRemoveChangesModeAndSignedHello(t *testing.T) {
	for _, mode := range []string{security.TranscriptCapabilitiesV1, security.TranscriptFullBindingV1} {
		for _, side := range []string{"client", "server"} {
			for _, action := range []string{"add", "remove"} {
				t.Run(mode+"/"+side+"/"+action, func(t *testing.T) {
					fixture := newFirstContactFixture(t, mode)
					extra := ir.SecurityCapabilities()[3]
					baseOffer := append([]string(nil), fixture.input.SelectedCapabilities...)
					extraOffer := append(append([]string(nil), baseOffer...), extra)
					oldInput, newInput := fixture.input, fixture.input
					if action == "add" {
						newInput = rebuildPeerOffer(t, fixture.profile, newInput, side, extraOffer)
					} else {
						oldInput = rebuildPeerOffer(t, fixture.profile, oldInput, side, extraOffer)
					}
					oldBinding := canonicalModeBindingForInput(t, oldInput)
					newBinding := canonicalModeBindingForInput(t, newInput)
					if bytes.Equal(oldBinding, newBinding) {
						t.Fatal("optional-capability source change did not change local ModeBindingV1 bytes")
					}

					var clientPublic, clientNonce, serverPublic, serverNonce [32]byte
					clientPublic[0], clientNonce[0], serverPublic[0], serverNonce[0] = 1, 2, 3, 4
					oldClientHello, oldClientBody, err := makeClientHello(oldInput.Client, fixture.clientPrivate, clientPublic, clientNonce)
					if err != nil {
						t.Fatal(err)
					}
					newClientHello, newClientBody, err := makeClientHello(newInput.Client, fixture.clientPrivate, clientPublic, clientNonce)
					if err != nil {
						t.Fatal(err)
					}

					if side == "client" {
						if bytes.Equal(oldClientHello, newClientHello) {
							t.Fatal("client optional source change did not change signed ClientHello")
						}
						newInput.InboundClientHello = oldClientHello
						result, err := FirstContact(newInput)
						assertClosedHandshakeCode(t, result, err, FailurePolicyMismatch)
					} else {
						oldServerHello, _, err := makeServerHello(oldInput, fixture.serverPrivate, oldClientBody, serverPublic, serverNonce)
						if err != nil {
							t.Fatal(err)
						}
						newServerHello, _, err := makeServerHello(newInput, fixture.serverPrivate, newClientBody, serverPublic, serverNonce)
						if err != nil {
							t.Fatal(err)
						}
						if bytes.Equal(oldServerHello, newServerHello) {
							t.Fatal("server optional source change did not change signed ServerHello")
						}
						var staleServerHello []byte
						result, err := firstContact(newInput, func(point mutationPoint, message []byte) []byte {
							switch point {
							case mutateClientHello:
								_, clientBody, parseErr := parseClientHello(message)
								if parseErr != nil {
									t.Fatal(parseErr)
								}
								staleServerHello, _, parseErr = makeServerHello(oldInput, fixture.serverPrivate, clientBody, serverPublic, serverNonce)
								if parseErr != nil {
									t.Fatal(parseErr)
								}
							case mutateServerHello:
								return staleServerHello
							}
							return message
						})
						assertClosedHandshakeCode(t, result, err, FailurePolicyMismatch)
					}
					newInput.InboundClientHello = nil
					if _, err := FirstContact(newInput); err != nil {
						t.Fatalf("valid changed optional source did not establish: %v", err)
					}
				})
			}
		}
	}
}

func TestHandshakeFloorSourceChangeRebuildsSignedHelloAndRejectsStaleSource(t *testing.T) {
	for _, side := range []string{"client", "server"} {
		t.Run(side, func(t *testing.T) {
			fixture := newFirstContactFixture(t, security.TranscriptCanonicalV1)
			known := ir.SecurityCapabilities()
			oldInput := fixture.input
			clientFloor := append([]string(nil), oldInput.Client.RequiredCapabilities...)
			serverFloor := append([]string(nil), oldInput.Server.RequiredCapabilities...)
			if side == "client" {
				clientFloor = append(clientFloor, known[1])
			} else {
				serverFloor = append(serverFloor, known[1])
			}
			newInput := rebuildPeerFloors(t, fixture.profile, oldInput, clientFloor, serverFloor)

			var clientPublic, clientNonce, serverPublic, serverNonce [32]byte
			clientPublic[0], clientNonce[0], serverPublic[0], serverNonce[0] = 1, 2, 3, 4
			oldClientHello, oldClientBody, err := makeClientHello(oldInput.Client, fixture.clientPrivate, clientPublic, clientNonce)
			if err != nil {
				t.Fatal(err)
			}
			newClientHello, newClientBody, err := makeClientHello(newInput.Client, fixture.clientPrivate, clientPublic, clientNonce)
			if err != nil {
				t.Fatal(err)
			}

			switch side {
			case "client":
				if bytes.Equal(oldClientHello, newClientHello) {
					t.Fatal("client floor source change did not change signed ClientHello")
				}
				stale := newInput
				stale.InboundClientHello = oldClientHello
				result, err := FirstContact(stale)
				assertClosedHandshakeCode(t, result, err, FailurePolicyFloorRejected)
			case "server":
				oldServerHello, _, err := makeServerHello(oldInput, fixture.serverPrivate, oldClientBody, serverPublic, serverNonce)
				if err != nil {
					t.Fatal(err)
				}
				newServerHello, _, err := makeServerHello(newInput, fixture.serverPrivate, newClientBody, serverPublic, serverNonce)
				if err != nil {
					t.Fatal(err)
				}
				if bytes.Equal(oldServerHello, newServerHello) {
					t.Fatal("server floor source change did not change signed ServerHello")
				}
				var staleServerHello []byte
				result, err := firstContact(newInput, func(point mutationPoint, message []byte) []byte {
					switch point {
					case mutateClientHello:
						_, clientBody, parseErr := parseClientHello(message)
						if parseErr != nil {
							t.Fatal(parseErr)
						}
						staleServerHello, _, parseErr = makeServerHello(oldInput, fixture.serverPrivate, clientBody, serverPublic, serverNonce)
						if parseErr != nil {
							t.Fatal(parseErr)
						}
					case mutateServerHello:
						return staleServerHello
					}
					return message
				})
				// The server floor is also committed into the selected-policy
				// field, which is deliberately checked before the floor field.
				assertClosedHandshakeCode(t, result, err, FailurePolicyMismatch)
			}

			established, err := FirstContact(newInput)
			if err != nil {
				t.Fatalf("valid changed floor source did not establish: %v", err)
			}
			if established.ClientState != StateEstablished || established.ServerState != StateAuthenticating || len(established.ChannelSecret) == 0 {
				t.Fatalf("valid changed floor source state = %s/%s with %d secret bytes", established.ClientState, established.ServerState, len(established.ChannelSecret))
			}
		})
	}
}

func rebuildPeerFloors(t *testing.T, profile *ir.Profile, input FirstContactInput, clientFloor, serverFloor []string) FirstContactInput {
	t.Helper()
	policy, err := ir.BuildEffectiveSecurityPolicy(profile, clientFloor, serverFloor, input.SelectedCapabilities)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewPeerParameters("client-test", profile, policy, policy, input.Client.OfferedCapabilities, clientFloor)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewPeerParameters("server-test", profile, policy, policy, input.Server.OfferedCapabilities, serverFloor)
	if err != nil {
		t.Fatal(err)
	}
	input.Client, input.Server, input.SelectedPolicy = client, server, policy
	return input
}

func rebuildPeerOffer(t *testing.T, profile *ir.Profile, input FirstContactInput, side string, offer []string) FirstContactInput {
	t.Helper()
	var err error
	switch side {
	case "client":
		input.Client, err = NewPeerParameters("client-test", profile, input.Client.OfferPolicy, input.Client.FloorPolicy, offer, input.Client.RequiredCapabilities)
	case "server":
		input.Server, err = NewPeerParameters("server-test", profile, input.Server.OfferPolicy, input.Server.FloorPolicy, offer, input.Server.RequiredCapabilities)
	default:
		t.Fatal("unknown optional-capability side")
	}
	if err != nil {
		t.Fatal(err)
	}
	return input
}

func canonicalModeBindingForInput(t *testing.T, input FirstContactInput) []byte {
	t.Helper()
	binding := input.Client.modeBinding
	binding.ClientOptional = optionalCapabilities(input.Client.OfferedCapabilities, input.Client.RequiredCapabilities)
	binding.ServerOptional = optionalCapabilities(input.Server.OfferedCapabilities, input.Server.RequiredCapabilities)
	raw, err := security.CanonicalHandshakeModeBinding(input.SelectedPolicy.TranscriptMode, binding)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestHandshakeModeBindingSourceMutationChangesSignedProfileCommitment(t *testing.T) {
	tests := map[string]struct {
		mode   string
		mutate func(*ir.Profile)
	}{
		"capability feature vector": {security.TranscriptCapabilitiesV1, func(p *ir.Profile) {
			p.Compatibility.SupportedProxyFeatures = p.Compatibility.SupportedProxyFeatures[1:]
		}},
		"carrier family": {security.TranscriptCarrierBindingV1, func(p *ir.Profile) {
			for _, family := range ir.CarrierFamilies() {
				if family != p.CarrierPolicy.CarrierFamily {
					p.CarrierPolicy.CarrierFamily = family
					return
				}
			}
		}},
		"carrier policy hash": {security.TranscriptCarrierBindingV1, func(p *ir.Profile) { p.CarrierPolicy.MaxRetryCount = (p.CarrierPolicy.MaxRetryCount + 1) % 4 }},
		"carrier envelope limit": {security.TranscriptCarrierBindingV1, func(p *ir.Profile) {
			if p.CarrierPolicy.MaxEnvelopeBytes > 1 {
				p.CarrierPolicy.MaxEnvelopeBytes--
			} else {
				p.CarrierPolicy.MaxEnvelopeBytes++
			}
		}},
		"carrier adapter": {security.TranscriptCarrierBindingV1, func(p *ir.Profile) {
			for _, value := range []string{"one_flow_one_stream", "priority_mapped_stream", "metadata_bound_stream", "state_derived_mapping"} {
				if value != p.AdapterPolicy.RuntimeMappingPolicy {
					p.AdapterPolicy.RuntimeMappingPolicy = value
					return
				}
			}
		}},
		"full framing hash": {security.TranscriptFullBindingV1, func(p *ir.Profile) {
			p.FrameGrammar.HeaderOrder[0], p.FrameGrammar.HeaderOrder[1] = p.FrameGrammar.HeaderOrder[1], p.FrameGrammar.HeaderOrder[0]
		}},
		"full state hash": {security.TranscriptFullBindingV1, func(p *ir.Profile) { p.Transitions[0].Description += "_mode_binding" }},
		"full scheduler hash": {security.TranscriptFullBindingV1, func(p *ir.Profile) {
			if p.Scheduler.FlushIntervalMs == 0 {
				p.Scheduler.FlushIntervalMs = 1
			} else {
				p.Scheduler.FlushIntervalMs--
			}
		}},
		"full padding hash": {security.TranscriptFullBindingV1, func(p *ir.Profile) {
			p.Padding = ir.PaddingPolicy{Mode: "fixed", MinPaddingBytes: 1, MaxPaddingBytes: 1}
		}},
		"full stream hash": {security.TranscriptFullBindingV1, func(p *ir.Profile) {
			if p.Stream.PriorityPolicy == "fifo" {
				p.Stream.PriorityPolicy = "interactive_first"
			} else {
				p.Stream.PriorityPolicy = "fifo"
			}
		}},
		"full proxy hash": {security.TranscriptFullBindingV1, func(p *ir.Profile) {
			if p.ProxySemantics.TargetMetadataPolicy == "none" {
				p.ProxySemantics.TargetMetadataPolicy = "pre_response_metadata"
			} else {
				p.ProxySemantics.TargetMetadataPolicy = "none"
			}
		}},
		"full carrier context hash": {security.TranscriptFullBindingV1, func(p *ir.Profile) {
			if p.AdapterPolicy.MaxEvents < 1<<20 {
				p.AdapterPolicy.MaxEvents++
			} else {
				p.AdapterPolicy.MaxEvents--
			}
		}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newFirstContactFixture(t, tt.mode)
			mutated := cloneProfile(t, fixture.profile)
			originalHash := mutated.GenerationHash
			tt.mutate(mutated)
			mutated.GenerationHash = ""
			mutatedHash, err := ir.CanonicalHash(mutated)
			if err != nil || mutatedHash == originalHash {
				t.Fatalf("source mutation did not change canonical profile hash: %v", err)
			}
			if _, err := NewPeerParameters("server-test", mutated, fixture.input.Server.OfferPolicy, fixture.input.Server.FloorPolicy, fixture.input.Server.OfferedCapabilities, fixture.input.Server.RequiredCapabilities); err == nil {
				t.Fatal("stale signed profile hash was accepted")
			}
			mutated.GenerationHash = mutatedHash
			if err := ir.Validate(mutated); err != nil {
				t.Fatalf("source mutation invalidated profile rather than changing its commitment: %v", err)
			}
			policy, err := ir.BuildEffectiveSecurityPolicy(mutated, fixture.input.Client.RequiredCapabilities, fixture.input.Server.RequiredCapabilities, fixture.input.SelectedCapabilities)
			if err != nil {
				t.Fatal(err)
			}
			peer, err := NewPeerParameters("server-test", mutated, policy, policy, fixture.input.Server.OfferedCapabilities, fixture.input.Server.RequiredCapabilities)
			if err != nil {
				t.Fatal(err)
			}
			var public, nonce [32]byte
			public[0], nonce[0] = 1, 2
			originalHello, _, err := makeClientHello(fixture.input.Server, fixture.serverPrivate, public, nonce)
			if err != nil {
				t.Fatal(err)
			}
			mutatedHello, _, err := makeClientHello(peer, fixture.serverPrivate, public, nonce)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(originalHello, mutatedHello) {
				t.Fatal("profile-derived source mutation did not change signed Hello bytes")
			}
			input := fixture.input
			input.Server = peer
			result, err := FirstContact(input)
			assertClosedHandshakeCode(t, result, err, FailureProfileMismatch)
		})
	}
}

func cloneProfile(t *testing.T, profile *ir.Profile) *ir.Profile {
	t.Helper()
	raw, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	var clone ir.Profile
	if err := json.Unmarshal(raw, &clone); err != nil {
		t.Fatal(err)
	}
	return &clone
}

func TestHandshakeOfferFloorSelectionAndAuthenticatorTamperMatrix(t *testing.T) {
	tests := []struct {
		name  string
		point mutationPoint
		field func(FirstContactInput) []byte
		want  FailureCode
	}{
		{"client offer", mutateClientHello, func(v FirstContactInput) []byte {
			raw, _ := encodePolicyOffer(v.Client.OfferPolicy, v.Client.OfferedCapabilities)
			return raw
		}, FailureSignatureInvalid},
		{"client floor", mutateClientHello, func(v FirstContactInput) []byte {
			raw, _ := encodeMandatoryFloor(v.Client.FloorPolicy, v.Client.RequiredCapabilities)
			return raw
		}, FailureSignatureInvalid},
		{"server offer", mutateServerHello, func(v FirstContactInput) []byte {
			raw, _ := encodePolicyOffer(v.Server.OfferPolicy, v.Server.OfferedCapabilities)
			return raw
		}, FailurePolicyMismatch},
		{"server floor", mutateServerHello, func(v FirstContactInput) []byte {
			raw, _ := encodeMandatoryFloor(v.Server.FloorPolicy, v.Server.RequiredCapabilities)
			return raw
		}, FailurePolicyFloorRejected},
		{"selected policy", mutateServerHello, func(v FirstContactInput) []byte {
			clientFloor, _ := encodeMandatoryFloor(v.Client.FloorPolicy, v.Client.RequiredCapabilities)
			serverFloor, _ := encodeMandatoryFloor(v.Server.FloorPolicy, v.Server.RequiredCapabilities)
			raw, _ := encodeSelectedPolicy(v.SelectedPolicy, v.SelectedCapabilities, clientFloor, serverFloor)
			return raw
		}, FailurePolicyMismatch},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := newFirstContactFixture(t, security.TranscriptFullBindingV1)
			_, err := firstContact(fixture.input, func(current mutationPoint, message []byte) []byte {
				if current == tt.point {
					flipOccurrence(t, message, tt.field(fixture.input))
				}
				return message
			})
			assertHandshakeCode(t, err, tt.want)
		})
	}
	for _, point := range []mutationPoint{mutateClientFinish, mutateServerFinish} {
		t.Run("finish confirmation", func(t *testing.T) {
			fixture := newFirstContactFixture(t, security.TranscriptFullBindingV1)
			_, err := firstContact(fixture.input, func(current mutationPoint, message []byte) []byte {
				if current == point {
					message[len(message)-1] ^= 1
				}
				return message
			})
			assertHandshakeCode(t, err, FailureKeyConfirmation)
		})
	}

	fixture := newFirstContactFixture(t, security.TranscriptCanonicalV1)
	substituted := fixture.input
	substituted.SelectedCapabilities = append([]string(nil), fixture.input.SelectedCapabilities[:2]...)
	_, err := FirstContact(substituted)
	assertHandshakeCode(t, err, FailurePolicyFloorRejected)
}

func TestHandshakeAllFivePolicyV1CopiesRejectOneFieldMismatch(t *testing.T) {
	tests := []struct {
		name       string
		point      mutationPoint
		occurrence int
		want       FailureCode
	}{
		{"client offer PolicyV1", mutateClientHello, 0, FailureSignatureInvalid},
		{"client floor PolicyV1", mutateClientHello, 1, FailureSignatureInvalid},
		{"server offer PolicyV1", mutateServerHello, 0, FailurePolicyMismatch},
		{"server floor PolicyV1", mutateServerHello, 1, FailurePolicyFloorRejected},
		{"selected PolicyV1", mutateServerHello, 2, FailurePolicyMismatch},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := newFirstContactFixture(t, security.TranscriptCanonicalV1)
			policy, err := security.EncodePolicyV1(fixture.input.SelectedPolicy)
			if err != nil {
				t.Fatal(err)
			}
			_, err = firstContact(fixture.input, func(point mutationPoint, message []byte) []byte {
				if point == tt.point {
					flipNthOccurrence(t, message, policy, tt.occurrence)
				}
				return message
			})
			assertHandshakeCode(t, err, tt.want)
		})
	}
}

func TestHandshakeDowngradePolicyAsymmetricFloorMatrix(t *testing.T) {
	for _, downgrade := range []string{"strict_suite_and_capabilities", "strict_capabilities", "suite_bound_transcript"} {
		t.Run(downgrade, func(t *testing.T) {
			fixture := newFirstContactFixture(t, security.TranscriptCanonicalV1)
			profile := cloneProfile(t, fixture.profile)
			profile.Security.DowngradePolicy = downgrade
			profile.GenerationHash = ""
			var err error
			profile.GenerationHash, err = ir.CanonicalHash(profile)
			if err != nil {
				t.Fatal(err)
			}
			known := ir.SecurityCapabilities()
			clientFloor := append([]string(nil), known[:2]...)
			serverFloor := append([]string(nil), known[1:3]...)
			selected := append([]string(nil), known[:3]...)
			clientOffer := append(append([]string(nil), selected...), known[3])
			serverOffer := append(append([]string(nil), selected...), known[4])
			policy, err := ir.BuildEffectiveSecurityPolicy(profile, clientFloor, serverFloor, selected)
			if err != nil {
				t.Fatal(err)
			}
			client, err := NewPeerParameters("client-test", profile, policy, policy, clientOffer, clientFloor)
			if err != nil {
				t.Fatal(err)
			}
			server, err := NewPeerParameters("server-test", profile, policy, policy, serverOffer, serverFloor)
			if err != nil {
				t.Fatal(err)
			}
			input := fixture.input
			input.Client, input.Server = client, server
			input.SelectedPolicy, input.SelectedCapabilities = policy, selected
			result, err := FirstContact(input)
			if downgrade == "strict_suite_and_capabilities" {
				assertClosedHandshakeCode(t, result, err, FailurePolicyFloorRejected)
				return
			}
			if err != nil {
				t.Fatalf("safe asymmetric bilateral floors rejected: %v", err)
			}
			if result.ClientState != StateEstablished {
				t.Fatal("safe asymmetric selection did not establish client")
			}
		})
	}

	fixture := newFirstContactFixture(t, security.TranscriptCanonicalV1)
	profile := cloneProfile(t, fixture.profile)
	profile.Security.DowngradePolicy = "strict_suite_and_capabilities"
	profile.GenerationHash = ""
	var err error
	profile.GenerationHash, err = ir.CanonicalHash(profile)
	if err != nil {
		t.Fatal(err)
	}
	floor := []string{ir.SecurityCapabilities()[0]}
	selected := append([]string(nil), ir.SecurityCapabilities()[:3]...)
	clientOffer := append(append([]string(nil), selected...), ir.SecurityCapabilities()[3])
	serverOffer := append(append([]string(nil), selected...), ir.SecurityCapabilities()[4])
	policy, err := ir.BuildEffectiveSecurityPolicy(profile, floor, floor, selected)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewPeerParameters("client-test", profile, policy, policy, clientOffer, floor)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewPeerParameters("server-test", profile, policy, policy, serverOffer, floor)
	if err != nil {
		t.Fatal(err)
	}
	input := fixture.input
	input.Client, input.Server, input.SelectedPolicy, input.SelectedCapabilities = client, server, policy, selected
	if _, err := FirstContact(input); err != nil {
		t.Fatalf("strict identical floors rejected: %v", err)
	}
}

func flipOccurrence(t *testing.T, message, field []byte) {
	t.Helper()
	index := bytes.Index(message, field)
	if index < 0 || len(field) == 0 {
		t.Fatal("target field not present in canonical message")
	}
	message[index+len(field)-1] ^= 1
}

func flipNthOccurrence(t *testing.T, message, field []byte, occurrence int) {
	t.Helper()
	searchFrom := 0
	for current := 0; ; current++ {
		relative := bytes.Index(message[searchFrom:], field)
		if relative < 0 {
			t.Fatalf("target occurrence %d not present", occurrence)
		}
		index := searchFrom + relative
		if current == occurrence {
			message[index+len(field)-1] ^= 1
			return
		}
		searchFrom = index + len(field)
	}
}

func exactModeVector(t *testing.T, mode string, binding security.HandshakeModeBinding) []byte {
	t.Helper()
	var out bytes.Buffer
	writeLP(&out, []byte("kurdistan/transcript/v1/"+mode))
	writeCaps := func() {
		for _, values := range [][]string{binding.ClientOptional, binding.ServerOptional, binding.FeatureVectors} {
			raw, err := security.EncodeStringListV1(values)
			if err != nil {
				t.Fatal(err)
			}
			writeLP(&out, raw)
		}
	}
	writeCarrier := func() {
		writeLP(&out, []byte(binding.CarrierFamily))
		out.Write(binding.CarrierPolicyHash[:])
		var raw [4]byte
		binary.BigEndian.PutUint32(raw[:], binding.EnvelopeLimit)
		out.Write(raw[:])
		writeLP(&out, []byte(binding.LocalAdapterClass))
	}
	switch mode {
	case security.TranscriptCapabilitiesV1:
		writeCaps()
	case security.TranscriptCarrierBindingV1:
		writeCarrier()
	case security.TranscriptFullBindingV1:
		writeCaps()
		writeCarrier()
		for _, value := range [][32]byte{binding.FramingPolicyHash, binding.StateMachinePolicyHash, binding.SchedulerPolicyHash, binding.PaddingPolicyHash, binding.StreamPolicyHash, binding.ProxyPolicyHash, binding.CarrierContextHash} {
			out.Write(value[:])
		}
	}
	return out.Bytes()
}

func assertHandshakeCode(t *testing.T, err error, code FailureCode) {
	t.Helper()
	var typed *HandshakeError
	if !errors.Is(err, ErrHandshake) || !errors.As(err, &typed) || typed.Code != code {
		t.Fatalf("error = %v, want %s", err, code)
	}
}

func assertClosedHandshakeCode(t *testing.T, result FirstContactResult, err error, code FailureCode) {
	t.Helper()
	assertHandshakeCode(t, err, code)
	if result.ClientState != StateClosed || result.ServerState != StateClosed || len(result.ChannelSecret) != 0 {
		t.Fatalf("failure state = %s/%s with %d secret bytes, want closed/closed and no secret", result.ClientState, result.ServerState, len(result.ChannelSecret))
	}
	if _, ok := result.AuthenticatedContextSnapshotV1(); ok {
		t.Fatal("failed result exposed authenticated context")
	}
}

func TestCredentialCasesUseNoSerializedOrSharedPrivateBytes(t *testing.T) {
	a := newFirstContactFixture(t, security.TranscriptCanonicalV1)
	b := newFirstContactFixture(t, security.TranscriptCanonicalV1)
	if slices.Equal(a.clientPrivate, b.clientPrivate) || slices.Equal(a.serverPrivate, b.serverPrivate) {
		t.Fatal("fresh fixture identities were reused")
	}
	result, err := FirstContact(a.input)
	if err != nil {
		t.Fatal(err)
	}
	for index, message := range result.Messages {
		for _, secret := range [][]byte{a.clientPrivate, a.clientPrivate[:ed25519.SeedSize], a.serverPrivate, a.serverPrivate[:ed25519.SeedSize]} {
			if bytes.Contains(message, secret) {
				t.Fatalf("message %d serialized private credential bytes", index)
			}
		}
	}
	failing := a.input
	failing.ServerDependencies.Trust = memoryTrust{"client-test", a.serverPublic}
	failureResult, failureErr := FirstContact(failing)
	assertClosedHandshakeCode(t, failureResult, failureErr, FailureSignatureInvalid)
	for _, secret := range [][]byte{a.clientPrivate, a.clientPrivate[:ed25519.SeedSize], a.serverPrivate, a.serverPrivate[:ed25519.SeedSize]} {
		if bytes.Contains([]byte(failureErr.Error()), secret) {
			t.Fatal("typed error serialized private credential bytes")
		}
	}
}

type exportedSentinelIdentity struct {
	ID       string
	Sentinel string
	Key      ed25519.PrivateKey
}

func (p exportedSentinelIdentity) Local(id string) (ed25519.PrivateKey, error) {
	if id != p.ID {
		return nil, errors.New("unknown")
	}
	return append(ed25519.PrivateKey(nil), p.Key...), nil
}

func TestHandshakeInputsAndResultsDoNotSerializeSecrets(t *testing.T) {
	fixture := newFirstContactFixture(t, security.TranscriptCanonicalV1)
	result, err := FirstContact(fixture.input)
	if err != nil {
		t.Fatal(err)
	}
	rawResult, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	encodedSecret := base64.StdEncoding.EncodeToString(result.ChannelSecret)
	if bytes.Contains(rawResult, result.ChannelSecret) || bytes.Contains(rawResult, []byte(encodedSecret)) || strings.Contains(strings.ToLower(string(rawResult)), "channelsecret") || strings.Contains(strings.ToLower(string(rawResult)), "channel_secret") {
		t.Fatal("successful result serialized channel keying material")
	}

	const sentinel = "provider-secret-sentinel"
	input := fixture.input
	input.ClientDependencies.Identity = exportedSentinelIdentity{ID: "client-test", Sentinel: sentinel, Key: fixture.clientPrivate}
	rawInput, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(rawInput, []byte(sentinel)) || bytes.Contains(rawInput, fixture.clientPrivate) {
		t.Fatal("FirstContactInput serialized injected provider state")
	}
}

func TestHandshakeRejectsRawAndMutatedPeerParameters(t *testing.T) {
	fixture := newFirstContactFixture(t, security.TranscriptFullBindingV1)
	for name, mutate := range map[string]func(*FirstContactInput){
		"raw zero peer":       func(v *FirstContactInput) { v.Client = PeerParameters{} },
		"identity after seal": func(v *FirstContactInput) { v.Client.IdentityID = "changed" },
		"offer after seal":    func(v *FirstContactInput) { v.Client.OfferedCapabilities = v.Client.OfferedCapabilities[:1] },
		"floor after seal": func(v *FirstContactInput) {
			v.Client.RequiredCapabilities = append(v.Client.RequiredCapabilities, "proxy_semantics")
		},
	} {
		t.Run(name, func(t *testing.T) {
			input := fixture.input
			mutate(&input)
			result, err := FirstContact(input)
			assertClosedHandshakeCode(t, result, err, FailureProfileMismatch)
		})
	}
}

func TestHandshakeBindsEffectivePolicyCapabilityIdentities(t *testing.T) {
	fixture := newFirstContactFixture(t, security.TranscriptCanonicalV1)
	known := ir.SecurityCapabilities()

	t.Run("required set disagrees with selected carrier", func(t *testing.T) {
		misbound, err := NewPeerParameters(
			"client-test", fixture.profile,
			fixture.input.Client.OfferPolicy, fixture.input.Client.FloorPolicy,
			fixture.input.Client.OfferedCapabilities, []string{known[1]},
		)
		if err != nil {
			t.Fatal(err)
		}
		input := fixture.input
		input.Client = misbound
		_, err = FirstContact(input)
		assertHandshakeCode(t, err, FailurePolicyFloorRejected)
	})

	t.Run("sealed offer carrier disagrees despite equal PolicyV1", func(t *testing.T) {
		alternate, err := ir.BuildEffectiveSecurityPolicy(
			fixture.profile,
			[]string{known[1]},
			fixture.input.SelectedPolicy.ServerMandatoryCapabilities,
			fixture.input.SelectedCapabilities,
		)
		if err != nil {
			t.Fatal(err)
		}
		misbound, err := NewPeerParameters(
			"client-test", fixture.profile,
			alternate, fixture.input.Client.FloorPolicy,
			fixture.input.Client.OfferedCapabilities, fixture.input.Client.RequiredCapabilities,
		)
		if err != nil {
			t.Fatal(err)
		}
		left, _ := security.EncodePolicyV1(alternate)
		right, _ := security.EncodePolicyV1(fixture.input.SelectedPolicy)
		if !bytes.Equal(left, right) {
			t.Fatal("test requires equal PolicyV1 bytes with different sealed capability carriers")
		}
		input := fixture.input
		input.Client = misbound
		_, err = FirstContact(input)
		assertHandshakeCode(t, err, FailurePolicyFloorRejected)
	})
}

func TestAuthenticatedContextV1SuccessCloneAndIndependentRecomputation(t *testing.T) {
	fixture := newFirstContactFixture(t, security.TranscriptFullBindingV1)
	result, err := FirstContact(fixture.input)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, ok := result.AuthenticatedContextSnapshotV1()
	if !ok {
		t.Fatal("successful result did not expose context")
	}
	if snapshot.TranscriptHash != result.TranscriptHash || snapshot.EffectivePolicy.ProfileHash != fixture.input.SelectedPolicy.ProfileHash {
		t.Fatal("context identity differs from successful handshake")
	}
	wantPolicyHash, err := security.EffectivePolicyHashV1(fixture.input.SelectedPolicy)
	if err != nil || snapshot.EffectivePolicyHash != wantPolicyHash {
		t.Fatalf("effective policy hash mismatch: %v", err)
	}
	wantCapabilityHash, err := security.SelectedCapabilityHashV1(fixture.input.SelectedPolicy.SelectedCapabilities)
	if err != nil || snapshot.SelectedCapabilityHash != wantCapabilityHash {
		t.Fatalf("selected capability hash mismatch: %v", err)
	}
	wantContextHash, err := security.ContextHashV1(security.AuthenticatedContextHashInputV1{
		EffectivePolicy: snapshot.EffectivePolicy, EffectivePolicyHash: snapshot.EffectivePolicyHash,
		TranscriptHash: snapshot.TranscriptHash, SelectedSuite: snapshot.SelectedSuite,
		SelectedCapabilityHash: snapshot.SelectedCapabilityHash, ClientProfileHash: snapshot.ClientProfileHash,
		ServerProfileHash: snapshot.ServerProfileHash, ClientModeBinding: snapshot.ClientModeBinding,
		ServerModeBinding: snapshot.ServerModeBinding,
	})
	if err != nil || snapshot.ContextHash != wantContextHash {
		t.Fatalf("context hash mismatch: %v", err)
	}
	if snapshot.ClientCompatibilityBlockHash != snapshot.ClientModeBinding.CompatibilityBlockHash ||
		snapshot.ClientLimitBlockHash != snapshot.ClientModeBinding.LimitBlockHash ||
		snapshot.ClientConfigSourceBlockHash != snapshot.ClientModeBinding.ConfigSourceBlockHash {
		t.Fatal("context did not retain separate client block hashes")
	}
	copyResult := result
	if _, ok := copyResult.AuthenticatedContextSnapshotV1(); !ok {
		t.Fatal("ordinary valid result copy lost its seal")
	}
	first := snapshot.ClientCompatibilityBlock.RequiredCapabilities[0]
	snapshot.ClientCompatibilityBlock.RequiredCapabilities[0] = "mutated"
	snapshot.ClientModeBinding.FeatureVectors[0] = "mutated"
	snapshot.EffectivePolicy.SelectedCapabilities[0] = "mutated"
	again, ok := result.AuthenticatedContextSnapshotV1()
	if !ok || again.ClientCompatibilityBlock.RequiredCapabilities[0] != first || again.ClientModeBinding.FeatureVectors[0] == "mutated" || again.EffectivePolicy.SelectedCapabilities[0] == "mutated" {
		t.Fatal("context accessor returned an alias")
	}
}

func TestAuthenticatedContextSnapshotV1RejectsEveryResultMutationAndFailure(t *testing.T) {
	mutations := map[string]func(*FirstContactResult){
		"client state":   func(v *FirstContactResult) { v.ClientState = StateClosed },
		"server state":   func(v *FirstContactResult) { v.ServerState = StateEstablished },
		"client nonce":   func(v *FirstContactResult) { v.ClientNonce[0] ^= 1 },
		"server nonce":   func(v *FirstContactResult) { v.ServerNonce[0] ^= 1 },
		"client public":  func(v *FirstContactResult) { v.ClientPublic[0] ^= 1 },
		"server public":  func(v *FirstContactResult) { v.ServerPublic[0] ^= 1 },
		"transcript":     func(v *FirstContactResult) { v.TranscriptHash[0] ^= 1 },
		"channel secret": func(v *FirstContactResult) { v.ChannelSecret[0] ^= 1 },
		"client hello":   func(v *FirstContactResult) { v.Messages[0][0] ^= 1 },
		"server hello":   func(v *FirstContactResult) { v.Messages[1][0] ^= 1 },
		"client finish":  func(v *FirstContactResult) { v.Messages[2][0] ^= 1 },
		"server finish":  func(v *FirstContactResult) { v.Messages[3][0] ^= 1 },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			fixture := newFirstContactFixture(t, security.TranscriptCanonicalV1)
			result, err := FirstContact(fixture.input)
			if err != nil {
				t.Fatal(err)
			}
			mutate(&result)
			if _, ok := result.AuthenticatedContextSnapshotV1(); ok {
				t.Fatal("mutated result retained context")
			}
		})
	}
	if _, ok := (FirstContactResult{}).AuthenticatedContextSnapshotV1(); ok {
		t.Fatal("zero result exposed context")
	}
	fixture := newFirstContactFixture(t, security.TranscriptCanonicalV1)
	result, err := FirstContact(fixture.input)
	if err != nil {
		t.Fatal(err)
	}
	reconstructed := FirstContactResult{
		ClientState: result.ClientState, ServerState: result.ServerState, ClientNonce: result.ClientNonce,
		ServerNonce: result.ServerNonce, ClientPublic: result.ClientPublic, ServerPublic: result.ServerPublic,
		TranscriptHash: result.TranscriptHash, ChannelSecret: append([]byte(nil), result.ChannelSecret...), Messages: result.Messages,
	}
	if _, ok := reconstructed.AuthenticatedContextSnapshotV1(); ok {
		t.Fatal("reconstructed public result exposed context")
	}
	if _, ok := closeResult(result).AuthenticatedContextSnapshotV1(); ok {
		t.Fatal("closeResult retained context")
	}
}

func TestSnapshotFirstContactInputV1DeepClonePreflightAndOriginalSeal(t *testing.T) {
	fixture := newFirstContactFixture(t, security.TranscriptFullBindingV1)
	snapshot, view, err := SnapshotFirstContactInputV1(fixture.input)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.ClientDependencies != (Dependencies{}) || snapshot.ServerDependencies != (Dependencies{}) || snapshot.Replay != nil {
		t.Fatal("snapshot retained executable authority")
	}
	if len(view.ClientModeBinding.FeatureVectors) == 0 || len(view.ServerModeBinding.FeatureVectors) == 0 {
		t.Fatal("preflight omitted projected mode binding")
	}
	executable := cloneFirstContactInput(snapshot)
	executable.ClientDependencies = fixture.input.ClientDependencies
	executable.ServerDependencies = fixture.input.ServerDependencies
	executable.Replay = fixture.input.Replay
	snapshot.Client.OfferedCapabilities[0] = "mutated"
	snapshot.SelectedCapabilities[0] = "mutated"
	view.ClientModeBinding.FeatureVectors[0] = "mutated"
	view.SelectedPolicy.SelectedCapabilities[0] = "mutated"
	if fixture.input.Client.OfferedCapabilities[0] == "mutated" || fixture.input.SelectedCapabilities[0] == "mutated" || fixture.input.Client.modeBinding.FeatureVectors[0] == "mutated" {
		t.Fatal("snapshot or view aliased caller input")
	}
	if _, err := FirstContact(executable); err != nil {
		t.Fatalf("verified clone could not be resealed and executed: %v", err)
	}
	invalid := fixture.input
	invalid.Client.IdentityID = "mutated-after-seal"
	if _, _, err := SnapshotFirstContactInputV1(invalid); err == nil {
		t.Fatal("original invalid peer seal was laundered")
	}
	oversize := fixture.input
	oversize.InboundClientHello = make([]byte, 4+maxHandshakeBody+1)
	if _, _, err := SnapshotFirstContactInputV1(oversize); err == nil {
		t.Fatal("oversize inbound hello accepted")
	}
}

func TestFirstContactPreflightProjectionIdempotentMismatchAndAsymmetry(t *testing.T) {
	t.Run("populated equal projection", func(t *testing.T) {
		fixture := newFirstContactFixture(t, security.TranscriptFullBindingV1)
		client, server, err := projectedModeBindings(fixture.input)
		if err != nil {
			t.Fatal(err)
		}
		fixture.input.Client.modeBinding = client
		fixture.input.Server.modeBinding = server
		fixture.input.Client.seal, _ = sealPeerParameters(fixture.input.Client)
		fixture.input.Server.seal, _ = sealPeerParameters(fixture.input.Server)
		if _, err := FirstContact(fixture.input); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("populated mismatch", func(t *testing.T) {
		fixture := newFirstContactFixture(t, security.TranscriptFullBindingV1)
		client, _, err := projectedModeBindings(fixture.input)
		if err != nil {
			t.Fatal(err)
		}
		client.ClientOptional = append(client.ClientOptional, "transcript_binding")
		sort.Strings(client.ClientOptional)
		fixture.input.Client.modeBinding = client
		fixture.input.Client.seal, _ = sealPeerParameters(fixture.input.Client)
		if _, _, err := SnapshotFirstContactInputV1(fixture.input); err == nil {
			t.Fatal("mismatched populated projection accepted")
		}
	})
	t.Run("asymmetric role optionals", func(t *testing.T) {
		fixture := newFirstContactFixture(t, security.TranscriptFullBindingV1)
		known := ir.SecurityCapabilities()
		floor := []string{known[0]}
		clientOffer := append(append([]string(nil), floor...), known[1])
		serverOffer := append(append([]string(nil), floor...), known[2])
		policy, err := ir.BuildEffectiveSecurityPolicy(fixture.profile, floor, floor, floor)
		if err != nil {
			t.Fatal(err)
		}
		fixture.input.Client, err = NewPeerParameters("client-test", fixture.profile, policy, policy, clientOffer, floor)
		if err != nil {
			t.Fatal(err)
		}
		fixture.input.Server, err = NewPeerParameters("server-test", fixture.profile, policy, policy, serverOffer, floor)
		if err != nil {
			t.Fatal(err)
		}
		fixture.input.SelectedPolicy = policy
		fixture.input.SelectedCapabilities = floor
		_, view, err := SnapshotFirstContactInputV1(fixture.input)
		if err != nil {
			t.Fatal(err)
		}
		if slices.Equal(view.ClientModeBinding.ClientOptional, view.ClientModeBinding.ServerOptional) {
			t.Fatal("asymmetric role optionals collapsed")
		}
	})
}

func TestPeerParameterCanonicalizationAndContextRange(t *testing.T) {
	fixture := newFirstContactFixture(t, security.TranscriptFullBindingV1)
	p := *fixture.profile
	p.Compatibility = fixture.profile.Compatibility
	p.Compatibility.SupportedSecuritySuites = slices.Clone(fixture.profile.Compatibility.SupportedSecuritySuites)
	p.Compatibility.RequiredCapabilities = slices.Clone(fixture.profile.Compatibility.RequiredCapabilities)
	p.Compatibility.SupportedCarrierFamilies = slices.Clone(fixture.profile.Compatibility.SupportedCarrierFamilies)
	p.Compatibility.SupportedProxyFeatures = slices.Clone(fixture.profile.Compatibility.SupportedProxyFeatures)
	p.Compatibility.SupportedStreamFeatures = slices.Clone(fixture.profile.Compatibility.SupportedStreamFeatures)
	slices.Reverse(p.Compatibility.RequiredCapabilities)
	slices.Reverse(p.Compatibility.SupportedProxyFeatures)
	slices.Reverse(p.Compatibility.SupportedStreamFeatures)
	p.GenerationHash = ""
	var err error
	p.GenerationHash, err = ir.CanonicalHash(&p)
	if err != nil {
		t.Fatal(err)
	}
	offered := slices.Clone(fixture.input.Client.OfferedCapabilities)
	required := slices.Clone(fixture.input.Client.RequiredCapabilities)
	slices.Reverse(offered)
	slices.Reverse(required)
	originalOffered := slices.Clone(offered)
	originalRequired := slices.Clone(required)
	policy, err := ir.BuildEffectiveSecurityPolicy(&p, required, required, offered)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := NewPeerParameters("client-test", &p, policy, policy, offered, required)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(offered, originalOffered) || !slices.Equal(required, originalRequired) {
		t.Fatal("NewPeerParameters mutated caller sets")
	}
	if !slices.IsSorted(peer.OfferedCapabilities) || !slices.IsSorted(peer.RequiredCapabilities) ||
		!slices.IsSorted(peer.modeBinding.CompatibilityBlock.RequiredCapabilities) ||
		!slices.IsSorted(peer.modeBinding.FeatureVectors) {
		t.Fatal("NewPeerParameters did not canonicalize set-like sources")
	}
	if peer.modeBinding.LimitBlock.MaxStates != uint32(p.Limits.MaxStates) ||
		peer.modeBinding.LimitBlock.MaxTransitions != uint32(p.Limits.MaxTransitions) ||
		peer.modeBinding.LimitBlock.MaxSessionMillis != uint64(p.Limits.MaxSessionMillis) {
		t.Fatal("signed range sources were not retained exactly")
	}
	if _, err := positiveU32(-1); err == nil {
		t.Fatal("negative U32 source accepted")
	}
	if ^uint(0) > uint(^uint32(0)) {
		if _, err := positiveU32(int(uint64(^uint32(0)) + 1)); err == nil {
			t.Fatal("overflowed U32 source accepted")
		}
	}
	if _, err := positiveU64(-1); err == nil {
		t.Fatal("negative U64 source accepted")
	}
}

func TestAuthenticatedContextV1ExactAPISignaturesCompile(t *testing.T) {
	var snapshot func(FirstContactInput) (FirstContactInput, FirstContactPreflightViewV1, error) = SnapshotFirstContactInputV1
	var accessor func(FirstContactResult) (AuthenticatedContextSnapshotV1, bool) = FirstContactResult.AuthenticatedContextSnapshotV1
	if snapshot == nil || accessor == nil {
		t.Fatal("exact context API is unavailable")
	}
}

func TestContextCloneEveryMutableSourceAndReturnPath(t *testing.T) {
	t.Run("profile source does not alias sealed peer", func(t *testing.T) {
		fixture := newFirstContactFixture(t, security.TranscriptFullBindingV1)
		peer := fixture.input.Client
		want := peer.modeBinding.Clone()
		profileLists := []*[]string{
			&fixture.profile.Compatibility.SupportedSecuritySuites,
			&fixture.profile.Compatibility.RequiredCapabilities,
			&fixture.profile.Compatibility.SupportedCarrierFamilies,
			&fixture.profile.Compatibility.SupportedProxyFeatures,
			&fixture.profile.Compatibility.SupportedStreamFeatures,
		}
		for _, values := range profileLists {
			if len(*values) > 0 {
				(*values)[0] = "mutated-profile-source"
			}
		}
		if !slices.Equal(peer.modeBinding.CompatibilityBlock.SupportedSecuritySuites, want.CompatibilityBlock.SupportedSecuritySuites) ||
			!slices.Equal(peer.modeBinding.CompatibilityBlock.RequiredCapabilities, want.CompatibilityBlock.RequiredCapabilities) ||
			!slices.Equal(peer.modeBinding.CompatibilityBlock.SupportedCarrierFamilies, want.CompatibilityBlock.SupportedCarrierFamilies) ||
			!slices.Equal(peer.modeBinding.CompatibilityBlock.SupportedProxyFeatures, want.CompatibilityBlock.SupportedProxyFeatures) ||
			!slices.Equal(peer.modeBinding.CompatibilityBlock.SupportedStreamFeatures, want.CompatibilityBlock.SupportedStreamFeatures) {
			t.Fatal("sealed peer retained a caller profile-list alias")
		}
	})

	t.Run("input snapshot and preflight are mutually independent", func(t *testing.T) {
		fixture := newFirstContactFixture(t, security.TranscriptFullBindingV1)
		fixture.input.InboundClientHello = []byte{0, 0, 0, 0}
		snapshot, view, err := SnapshotFirstContactInputV1(fixture.input)
		if err != nil {
			t.Fatal(err)
		}
		wantSnapshot := cloneFirstContactInput(snapshot)
		wantView := clonePreflightView(view)
		mutateFirstContactInputSlices(&fixture.input)
		if !reflect.DeepEqual(snapshot, wantSnapshot) {
			t.Fatal("snapshot aliases caller input")
		}
		mutateFirstContactInputSlices(&snapshot)
		if !reflect.DeepEqual(view, wantView) {
			t.Fatal("preflight view aliases returned snapshot")
		}
		wantMutatedSnapshot := cloneFirstContactInput(snapshot)
		mutatePreflightViewSlices(&view)
		if !reflect.DeepEqual(snapshot, wantMutatedSnapshot) {
			t.Fatal("preflight view mutation reached snapshot source")
		}
	})

	t.Run("context accessor clones every nested list", func(t *testing.T) {
		fixture := newFirstContactFixture(t, security.TranscriptFullBindingV1)
		result, err := FirstContact(fixture.input)
		if err != nil {
			t.Fatal(err)
		}
		first, ok := result.AuthenticatedContextSnapshotV1()
		if !ok {
			t.Fatal("missing context")
		}
		want := cloneContextSnapshot(first)
		mutateContextSnapshotSlices(&first)
		again, ok := result.AuthenticatedContextSnapshotV1()
		if !ok || !reflect.DeepEqual(again, want) {
			t.Fatal("context accessor retained a nested alias")
		}
	})
}

func TestContextFailureMatrixClearsContextAndSuccessSeal(t *testing.T) {
	cases := []struct {
		name string
		run  func(*testing.T) (FirstContactResult, error)
	}{
		{"early invalid peer seal", func(t *testing.T) (FirstContactResult, error) {
			fixture := newFirstContactFixture(t, security.TranscriptCanonicalV1)
			fixture.input.Client.IdentityID = "changed-after-seal"
			return FirstContact(fixture.input)
		}},
		{"replay", func(t *testing.T) (FirstContactResult, error) {
			fixture := newFirstContactFixture(t, security.TranscriptCanonicalV1)
			first, err := FirstContact(fixture.input)
			if err != nil {
				t.Fatal(err)
			}
			fixture.input.InboundClientHello = append([]byte(nil), first.Messages[0]...)
			return FirstContact(fixture.input)
		}},
		{"trust", func(t *testing.T) (FirstContactResult, error) {
			fixture := newFirstContactFixture(t, security.TranscriptCanonicalV1)
			fixture.input.ClientDependencies.Trust = memoryTrust{"server-test", make(ed25519.PublicKey, ed25519.PublicKeySize)}
			return FirstContact(fixture.input)
		}},
		{"entropy", func(t *testing.T) (FirstContactResult, error) {
			fixture := newFirstContactFixture(t, security.TranscriptCanonicalV1)
			return firstContactWithOptions(fixture.input, executionOptions{clientEntropy: errorReader{}})
		}},
		{"policy", func(t *testing.T) (FirstContactResult, error) {
			fixture := newFirstContactFixture(t, security.TranscriptCanonicalV1)
			fixture.input.SelectedCapabilities = append([]string(nil), fixture.input.SelectedCapabilities[:1]...)
			return FirstContact(fixture.input)
		}},
		{"confirmation", func(t *testing.T) (FirstContactResult, error) {
			fixture := newFirstContactFixture(t, security.TranscriptCanonicalV1)
			return firstContact(fixture.input, func(point mutationPoint, message []byte) []byte {
				if point == mutateServerFinish {
					message[len(message)-1] ^= 1
				}
				return message
			})
		}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.run(t)
			if err == nil {
				t.Fatal("failure case succeeded")
			}
			if result.ClientState != StateClosed || result.ServerState != StateClosed || len(result.ChannelSecret) != 0 ||
				!isZero32(result.successSeal) || !isZero32(result.context.seal) {
				t.Fatalf("failure retained success state: states=%s/%s secret=%d", result.ClientState, result.ServerState, len(result.ChannelSecret))
			}
			if _, ok := result.AuthenticatedContextSnapshotV1(); ok {
				t.Fatal("failure exposed context")
			}
		})
	}
}

func TestAuthenticatedContextV1StaticAPIAndSecretScan(t *testing.T) {
	_, current, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate auth source")
	}
	authPath := filepath.Join(filepath.Dir(current), "handshake.go")
	securityPath := filepath.Join(filepath.Dir(current), "..", "security", "authenticated_context.go")
	fset := token.NewFileSet()
	authFile, err := parser.ParseFile(fset, authPath, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	securityFile, err := parser.ParseFile(fset, securityPath, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if declaresType(securityFile, "AuthenticatedContextV1") {
		t.Fatal("security package can assert authenticated-context provenance")
	}
	for _, declaration := range authFile.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if ast.IsExported(function.Name.Name) && strings.HasPrefix(function.Name.Name, "New") && strings.Contains(function.Name.Name, "Context") {
			t.Fatalf("public context constructor found: %s", function.Name.Name)
		}
		if ast.IsExported(function.Name.Name) && nodeNamesType(function.Type, "AuthenticatedContextV1") {
			t.Fatalf("opaque context crosses exported API: %s", function.Name.Name)
		}
		if receiverNamesType(function.Recv, "AuthenticatedContextV1") {
			lower := strings.ToLower(function.Name.Name)
			for _, forbidden := range []string{"marshal", "unmarshal", "encode", "decode", "gob", "format", "string", "text", "binary", "json"} {
				if strings.Contains(lower, forbidden) {
					t.Fatalf("opaque context has formatting/serialization method: %s", function.Name.Name)
				}
			}
		}
	}
	firstContactInput := findStruct(t, authFile, "FirstContactInput")
	for _, field := range firstContactInput.Fields.List {
		for _, name := range field.Names {
			lower := strings.ToLower(name.Name)
			for _, forbidden := range []string{"context", "transcripthash", "channelsecret", "modebinding", "contextHash"} {
				if strings.Contains(lower, strings.ToLower(forbidden)) {
					t.Fatalf("FirstContactInput accepts context override: %s", name.Name)
				}
			}
		}
	}
	opaque := findStruct(t, authFile, "AuthenticatedContextV1")
	for _, field := range opaque.Fields.List {
		for _, name := range field.Names {
			if ast.IsExported(name.Name) {
				t.Fatalf("opaque context field is exported: %s", name.Name)
			}
		}
	}
	snapshot := findStruct(t, authFile, "AuthenticatedContextSnapshotV1")
	for _, field := range snapshot.Fields.List {
		if nodeNamesType(field.Type, "Profile") || containsPointer(field.Type) {
			t.Fatal("context snapshot retains a profile pointer")
		}
		for _, name := range field.Names {
			lower := strings.ToLower(name.Name)
			for _, forbidden := range []string{"secret", "private", "traffic", "nonce", "proof", "rawmessage", "credential"} {
				if strings.Contains(lower, forbidden) {
					t.Fatalf("context snapshot exposes forbidden field: %s", name.Name)
				}
			}
		}
	}
	for _, path := range []string{authPath, securityPath} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(raw, []byte("func (c AuthenticatedContextV1) Marshal")) ||
			bytes.Contains(raw, []byte("func (c AuthenticatedContextV1) Format")) ||
			bytes.Contains(raw, []byte("func (c AuthenticatedContextV1) String")) {
			t.Fatal("opaque context has hidden formatting/serialization path")
		}
	}
}

func TestHandshakeVectorContextBlocksStayOutOfFrozenModeShape(t *testing.T) {
	fixture := newFirstContactFixture(t, security.TranscriptFullBindingV1)
	base := fixture.input.Client.modeBinding.Clone()
	base.ClientOptional = optionalCapabilities(fixture.input.Client.OfferedCapabilities, fixture.input.Client.RequiredCapabilities)
	base.ServerOptional = optionalCapabilities(fixture.input.Server.OfferedCapabilities, fixture.input.Server.RequiredCapabilities)
	frozenBefore, err := security.CanonicalHandshakeModeBinding(fixture.input.Client.OfferPolicy.TranscriptMode, base)
	if err != nil {
		t.Fatal(err)
	}
	contextBefore, err := security.CanonicalAuthenticatedModeBindingV1(fixture.input.Client.OfferPolicy.TranscriptMode, base)
	if err != nil {
		t.Fatal(err)
	}
	changed := base.Clone()
	changed.CompatibilityBlock.MaxEnvelopeBytes++
	changed.CompatibilityBlockHash, err = security.CompatibilityBlockHashV1(changed.CompatibilityBlock)
	if err != nil {
		t.Fatal(err)
	}
	changed.ConfigSourceBlock.CompatibilityBlockHash = changed.CompatibilityBlockHash
	changed.ConfigSourceBlockHash, err = security.ConfigSourceBlockHashV1(changed.ConfigSourceBlock)
	if err != nil {
		t.Fatal(err)
	}
	frozenAfter, err := security.CanonicalHandshakeModeBinding(fixture.input.Client.OfferPolicy.TranscriptMode, changed)
	if err != nil {
		t.Fatal(err)
	}
	contextAfter, err := security.CanonicalAuthenticatedModeBindingV1(fixture.input.Client.OfferPolicy.TranscriptMode, changed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(frozenBefore, frozenAfter) {
		t.Fatal("context blocks changed a frozen handshake mode shape")
	}
	if bytes.Equal(contextBefore, contextAfter) {
		t.Fatal("context block change did not change context-only binding")
	}
	peerBefore := fixture.input.Client
	peerAfter := clonePeerParameters(peerBefore)
	peerAfter.modeBinding = changed
	sealBefore, err := sealPeerParameters(peerBefore)
	if err != nil {
		t.Fatal(err)
	}
	sealAfter, err := sealPeerParameters(peerAfter)
	if err != nil {
		t.Fatal(err)
	}
	if sealBefore == sealAfter {
		t.Fatal("context block change did not change peer seal")
	}
}

func TestHandshakeVectorFrozenWireTranscriptConfirmationAndKeySchedule(t *testing.T) {
	t.Setenv("GODEBUG", "cryptocustomrand=1")
	input := deterministicVectorFirstContactInput(t)
	clientEntropy := bytes.Repeat([]byte{0x31}, 1024)
	serverEntropy := bytes.Repeat([]byte{0x92}, 1024)
	result, err := firstContactWithOptions(input, executionOptions{
		clientEntropy: bytes.NewReader(clientEntropy),
		serverEntropy: bytes.NewReader(serverEntropy),
	})
	if err != nil {
		t.Fatal(err)
	}
	var bodies [4][]byte
	for i, message := range result.Messages {
		bodies[i], err = decodeOuter(message)
		if err != nil {
			t.Fatal(err)
		}
	}
	th2 := protocolHash("kurdistan/handshake/v1/transcript-hello", bodies[0], bodies[1])
	th3 := protocolHash("kurdistan/handshake/v1/transcript-client-finish", bodies[0], bodies[1], bodies[2])
	th4 := protocolHash("kurdistan/handshake/v1/transcript-final", bodies[0], bodies[1], bodies[2], bodies[3])
	if th4 != result.TranscriptHash {
		t.Fatal("frozen TH4 recomputation differs from result")
	}
	schedule, err := security.DeriveKeyScheduleV1(security.KeyScheduleInput{
		ApplicationSecret: append([]byte(nil), result.ChannelSecret...),
		TranscriptHash:    append([]byte(nil), result.TranscriptHash[:]...),
		Suite:             policySuite(input.SelectedPolicy),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer schedule.Destroy()
	got := map[string]string{
		"client_hello_wire_sha256":       sha256Hex(result.Messages[0]),
		"server_hello_wire_sha256":       sha256Hex(result.Messages[1]),
		"client_finish_wire_sha256":      sha256Hex(result.Messages[2]),
		"server_finish_wire_sha256":      sha256Hex(result.Messages[3]),
		"client_hello_signature_sha256":  sha256Hex(bodies[0][len(bodies[0])-ed25519.SignatureSize:]),
		"server_hello_signature_sha256":  sha256Hex(bodies[1][len(bodies[1])-ed25519.SignatureSize:]),
		"client_finish_signature_sha256": sha256Hex(bodies[2][36:100]),
		"server_finish_signature_sha256": sha256Hex(bodies[3][36:100]),
		"client_confirmation":            hex.EncodeToString(bodies[2][100:]),
		"server_confirmation":            hex.EncodeToString(bodies[3][100:]),
		"th2":                            hex.EncodeToString(th2[:]),
		"th3":                            hex.EncodeToString(th3[:]),
		"th4":                            hex.EncodeToString(th4[:]),
		"channel_secret_sha256":          sha256Hex(result.ChannelSecret),
		"schedule_client_key":            hex.EncodeToString(schedule.ClientWriteKey),
		"schedule_server_key":            hex.EncodeToString(schedule.ServerWriteKey),
		"schedule_client_nonce":          hex.EncodeToString(schedule.ClientNonceBase),
		"schedule_server_nonce":          hex.EncodeToString(schedule.ServerNonceBase),
		"schedule_exporter":              hex.EncodeToString(schedule.ExporterSecret),
	}
	want := map[string]string{
		"channel_secret_sha256":          "19b52ca05249e24b7361eba958818b977fba8d99d56e54c329e0151a26da3638",
		"client_confirmation":            "6c7e266dc6a25512690fb2fa792136ddad82aa464be1dff6c16adba739761435",
		"client_finish_signature_sha256": "474e66a5d480860b3beb50882d9d964347d8f4f36ed643d4f1c852760d4d0723",
		"client_finish_wire_sha256":      "d5dd2e265fe5105930dc19eafca0a8cef4f78c7c7f3bd061e2ab0c1099998fc1",
		"client_hello_signature_sha256":  "29f3fd0a1e248d02f680cd22be735ea11c35d32080d9806b1d8af060e1551047",
		"client_hello_wire_sha256":       "7c921888b8abd6ea5d6a6caa5463753394dc548bdce97f51f665b2cc9ba0701f",
		"schedule_client_key":            "ace19ceb919a4bcc8c45dc95b530e19a05bc111ee19573c80c34884475be0feb",
		"schedule_client_nonce":          "69f9b4dbe34dc64555c62f1f",
		"schedule_exporter":              "ec9f3ed9b937064f46a78ae02ac61a31b204f30e8cfe8663f585a892ee773bb7",
		"schedule_server_key":            "5faec4dbea9424a128155d7aa34e5580c873a65418339dc0e42c9a78a3059fb5",
		"schedule_server_nonce":          "ddf963107122599eb89379f2",
		"server_confirmation":            "74bb73a69241c2522ca6c03195465171aa06601c6b80241e8cb3a51f1c2c746c",
		"server_finish_signature_sha256": "84082b84675eee4db7b6f0fb8cbaa8cc3548005f962cbf487fb3e36b6ccb354d",
		"server_finish_wire_sha256":      "9c8842d1a8bc6e475ae15fec0ce416a119a715e44666d76c1b88bb2a1d7f59ca",
		"server_hello_signature_sha256":  "0b625e4b6f61e8bf02e985b5eab3092550675ed3cd6ca549d81e37d333dec59d",
		"server_hello_wire_sha256":       "8d987cf7505759efb7fa6f1413df86c2e5435d6e72eb8433e639657a08bb0d6a",
		"th2":                            "dab8867f00fc5652e09c896597e4de835c3a70c2f9a60554e582417004d9faa2",
		"th3":                            "66dc8b3dfc6280a56d799eee74bcb0de718e3a3f05b9813cac88d3182b28fb85",
		"th4":                            "7ed9f951914f0a1bd9d91f660c51272d5e736404cc34006355dba51a049bfbf9",
	}
	names := make([]string, 0, len(want))
	for name := range want {
		names = append(names, name)
	}
	sort.Strings(names)
	var mismatches []string
	for _, name := range names {
		if got[name] != want[name] {
			mismatches = append(mismatches, fmt.Sprintf("%s=%s want %s", name, got[name], want[name]))
		}
	}
	if len(mismatches) != 0 {
		t.Fatalf("frozen handshake vector drift:\n%s", strings.Join(mismatches, "\n"))
	}
}

func TestPolicyMatrixAuthenticatedContextOwnerWitnessLiteralHandshakeV1(t *testing.T) {
	for _, mode := range []string{security.TranscriptCanonicalV1, security.TranscriptCapabilitiesV1, security.TranscriptCarrierBindingV1, security.TranscriptFullBindingV1} {
		t.Run(mode, func(t *testing.T) {
			fixture := newFirstContactFixture(t, mode)
			binding := fixture.input.Client.modeBinding
			binding.ClientOptional = optionalCapabilities(fixture.input.Client.OfferedCapabilities, fixture.input.Client.RequiredCapabilities)
			binding.ServerOptional = optionalCapabilities(fixture.input.Server.OfferedCapabilities, fixture.input.Server.RequiredCapabilities)
			encoded, err := security.CanonicalHandshakeModeBinding(mode, binding)
			if err != nil || !bytes.Equal(encoded, exactModeVector(t, mode, binding)) {
				t.Fatalf("valid transcript owner reached=%x err=%v", encoded, err)
			}
			if result, err := FirstContact(fixture.input); err != nil || result.TranscriptHash == ([32]byte{}) {
				t.Fatalf("valid first contact reached=%x err=%v", result.TranscriptHash, err)
			}
			mutations := 0
			_, actual := firstContactWithOptions(fixture.input, executionOptions{mutateClientTH2: func(transcript *[32]byte) {
				transcript[0] ^= 1
				mutations++
			}})
			if mutations != 1 || actual == nil || !errors.Is(actual, ErrHandshake) || actual.Error() != "authenticated first contact failed: key_confirmation_failed" {
				t.Fatalf("mutations=%d error=%v", mutations, actual)
			}
		})
	}
}

func mutateFirstContactInputSlices(input *FirstContactInput) {
	for _, peer := range []*PeerParameters{&input.Client, &input.Server} {
		mutateStringSlice(peer.OfferedCapabilities)
		mutateStringSlice(peer.RequiredCapabilities)
		mutatePolicySlices(&peer.OfferPolicy)
		mutatePolicySlices(&peer.FloorPolicy)
		mutateModeBindingSlices(&peer.modeBinding)
	}
	mutatePolicySlices(&input.SelectedPolicy)
	mutateStringSlice(input.SelectedCapabilities)
	if len(input.InboundClientHello) > 0 {
		input.InboundClientHello[0] ^= 1
	}
}

func mutatePreflightViewSlices(view *FirstContactPreflightViewV1) {
	for _, policy := range []*ir.EffectiveSecurityPolicy{
		&view.ClientOfferPolicy,
		&view.ClientFloorPolicy,
		&view.ServerOfferPolicy,
		&view.ServerFloorPolicy,
		&view.SelectedPolicy,
	} {
		mutatePolicySlices(policy)
	}
	for _, values := range [][]string{
		view.ClientOfferedCapabilities,
		view.ClientRequiredCapabilities,
		view.ServerOfferedCapabilities,
		view.ServerRequiredCapabilities,
		view.SelectedCapabilities,
	} {
		mutateStringSlice(values)
	}
	mutateModeBindingSlices(&view.ClientModeBinding)
	mutateModeBindingSlices(&view.ServerModeBinding)
}

func mutateContextSnapshotSlices(snapshot *AuthenticatedContextSnapshotV1) {
	mutatePolicySlices(&snapshot.EffectivePolicy)
	mutateCompatibilityBlockSlices(&snapshot.ClientCompatibilityBlock)
	mutateCompatibilityBlockSlices(&snapshot.ServerCompatibilityBlock)
	mutateModeBindingSlices(&snapshot.ClientModeBinding)
	mutateModeBindingSlices(&snapshot.ServerModeBinding)
}

func mutatePolicySlices(policy *ir.EffectiveSecurityPolicy) {
	mutateStringSlice(policy.ClientMandatoryCapabilities)
	mutateStringSlice(policy.ServerMandatoryCapabilities)
	mutateStringSlice(policy.SelectedCapabilities)
}

func mutateModeBindingSlices(binding *security.HandshakeModeBinding) {
	mutateStringSlice(binding.ClientOptional)
	mutateStringSlice(binding.ServerOptional)
	mutateStringSlice(binding.FeatureVectors)
	mutateCompatibilityBlockSlices(&binding.CompatibilityBlock)
}

func mutateCompatibilityBlockSlices(block *security.CompatibilityBlockV1) {
	mutateStringSlice(block.SupportedSecuritySuites)
	mutateStringSlice(block.RequiredCapabilities)
	mutateStringSlice(block.SupportedCarrierFamilies)
	mutateStringSlice(block.SupportedProxyFeatures)
	mutateStringSlice(block.SupportedStreamFeatures)
}

func mutateStringSlice(values []string) {
	if len(values) > 0 {
		values[0] = "mutated-list-value"
	}
}

func declaresType(file *ast.File, name string) bool {
	for _, declaration := range file.Decls {
		general, ok := declaration.(*ast.GenDecl)
		if !ok || general.Tok != token.TYPE {
			continue
		}
		for _, specification := range general.Specs {
			typeSpec, ok := specification.(*ast.TypeSpec)
			if ok && typeSpec.Name.Name == name {
				return true
			}
		}
	}
	return false
}

func findStruct(t *testing.T, file *ast.File, name string) *ast.StructType {
	t.Helper()
	for _, declaration := range file.Decls {
		general, ok := declaration.(*ast.GenDecl)
		if !ok || general.Tok != token.TYPE {
			continue
		}
		for _, specification := range general.Specs {
			typeSpec, ok := specification.(*ast.TypeSpec)
			if !ok || typeSpec.Name.Name != name {
				continue
			}
			value, ok := typeSpec.Type.(*ast.StructType)
			if !ok {
				t.Fatalf("%s is not a struct", name)
			}
			return value
		}
	}
	t.Fatalf("missing struct %s", name)
	return nil
}

func nodeNamesType(node ast.Node, name string) bool {
	found := false
	ast.Inspect(node, func(current ast.Node) bool {
		identifier, ok := current.(*ast.Ident)
		if ok && identifier.Name == name {
			found = true
			return false
		}
		return !found
	})
	return found
}

func receiverNamesType(fields *ast.FieldList, name string) bool {
	return fields != nil && nodeNamesType(fields, name)
}

func containsPointer(node ast.Node) bool {
	found := false
	ast.Inspect(node, func(current ast.Node) bool {
		if _, ok := current.(*ast.StarExpr); ok {
			found = true
			return false
		}
		return !found
	})
	return found
}

func deterministicVectorFirstContactInput(t *testing.T) FirstContactInput {
	t.Helper()
	p, err := compiler.Generate(6199)
	if err != nil {
		t.Fatal(err)
	}
	p.Security.TranscriptMode = security.TranscriptFullBindingV1
	p.Security.CapabilityNegotiationPolicy = "intersection_with_required"
	p.Security.DowngradePolicy = "strict_capabilities"
	p.GenerationHash = ""
	p.GenerationHash, err = ir.CanonicalHash(p)
	if err != nil {
		t.Fatal(err)
	}
	known := ir.SecurityCapabilities()
	floor := append([]string(nil), known[:1]...)
	selected := append([]string(nil), known[:3]...)
	policy, err := ir.BuildEffectiveSecurityPolicy(p, floor, floor, selected)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewPeerParameters("client-vector", p, policy, policy, selected, floor)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewPeerParameters("server-vector", p, policy, policy, selected, floor)
	if err != nil {
		t.Fatal(err)
	}
	clientSeed := bytes.Repeat([]byte{0x11}, ed25519.SeedSize)
	serverSeed := bytes.Repeat([]byte{0x22}, ed25519.SeedSize)
	clientPrivate := ed25519.NewKeyFromSeed(clientSeed)
	serverPrivate := ed25519.NewKeyFromSeed(serverSeed)
	clientPublic := append(ed25519.PublicKey(nil), clientPrivate[ed25519.SeedSize:]...)
	serverPublic := append(ed25519.PublicKey(nil), serverPrivate[ed25519.SeedSize:]...)
	replay, err := NewHandshakeReplayCache(64)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		wipe(clientPrivate)
		wipe(serverPrivate)
		wipe(clientSeed)
		wipe(serverSeed)
	})
	return FirstContactInput{
		Client: client, Server: server, SelectedPolicy: policy, SelectedCapabilities: selected,
		ClientDependencies: Dependencies{Identity: memoryIdentity{"client-vector", clientPrivate}, Trust: memoryTrust{"server-vector", serverPublic}},
		ServerDependencies: Dependencies{Identity: memoryIdentity{"server-vector", serverPrivate}, Trust: memoryTrust{"client-vector", clientPublic}},
		Replay:             replay,
	}
}

func sha256Hex(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}
