package main

import (
	"sort"
	"testing"
)

// frozenCommands is the kcheck CLI contract: the exact set of subsystem
// subcommands (excluding the bare/no-arg audit fallthrough). Adding or removing
// a name here is a CLI-surface change and must be a deliberate, reviewed edit
// (see planning contracts.md §1). This test guards the registry against
// accidental drift during the architecture-realignment restructure.
var frozenCommands = []string{
	"compare", "adversary", "codegen", "streamadversary", "proxysem", "carrier",
	"security", "runtime", "hardening", "adapter", "localadapter", "bytetransport",
	"fixtures", "bytepath", "protocorpus", "wirefeatures", "wiregen", "wireeval",
	"hostdetect", "relayfleet", "proxyingress", "localproxyingress",
	"localproxyingressadv", "adaptivepath", "transportbundle", "pathrace",
	"pathhealth", "carrierreview", "measurementreview", "proxyegress", "relaybridge",
	"localpipeline", "productionreadiness", "concretelocaladapter",
	"localprotocoladapter", "loopbackrelay", "labegress", "carrierreadiness",
	"httpscarrierreview", "httpslikecarrier", "httpscarrieradversary",
	"constrainedcarrierreview", "constrainedcarrier", "multicarrierselect",
	"carriercollapse", "localproxyadapterreview", "localproxyadapter",
	"vpnsemantics", "localvpnadapter", "relayprocess", "keyexchangeplan",
	"relayauthplan", "operationalhardening", "androidruntime", "androidvpnservice",
	"androidcarrier", "androidreview",
}

func TestCommandRegistryMatchesFrozenSurface(t *testing.T) {
	reg := commandRegistry()

	got := make([]string, 0, len(reg))
	for name, handler := range reg {
		if handler == nil {
			t.Errorf("command %q has a nil handler", name)
		}
		got = append(got, name)
	}
	sort.Strings(got)

	want := append([]string(nil), frozenCommands...)
	sort.Strings(want)

	if len(got) != len(want) {
		t.Fatalf("command-surface drift: registry has %d commands, frozen set has %d\n registry=%v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("command-surface drift at index %d: registry=%q frozen=%q", i, got[i], want[i])
		}
	}
}
