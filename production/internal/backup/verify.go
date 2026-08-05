// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package backup

import (
	"errors"
	"regexp"
)

var (
	ErrInvalid  = errors.New("backup: invalid evidence")
	ErrRollback = errors.New("backup: authority rollback")
	ErrFork     = errors.New("backup: authority fork")
	digestRE    = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type Head struct {
	Epoch        uint64
	Revision     uint64
	Sequence     uint64
	StateDigest  string
	AuditDigest  string
	PublicDigest string
}

type RestoreEvidence struct {
	Restored       Head
	PreIncident    Head
	ExternalAudit  Head
	ExternalPublic Head
	PendingOutbox  uint32
	SchemaVersion  string
}

type ReplayPlan struct {
	FromSequence uint64
	Count        uint32
	StateDigest  string
}

func VerifyRestore(evidence RestoreEvidence) (ReplayPlan, error) {
	if evidence.SchemaVersion != "phase16-spanner-authority-v1" || !validHead(evidence.Restored) ||
		!validHead(evidence.PreIncident) || !validHead(evidence.ExternalAudit) || !validHead(evidence.ExternalPublic) ||
		evidence.PendingOutbox > 100000 {
		return ReplayPlan{}, ErrInvalid
	}
	if evidence.Restored.Epoch < evidence.PreIncident.Epoch || evidence.Restored.Revision < evidence.PreIncident.Revision ||
		evidence.Restored.Sequence < evidence.ExternalAudit.Sequence || evidence.Restored.Sequence < evidence.ExternalPublic.Sequence {
		return ReplayPlan{}, ErrRollback
	}
	for _, external := range []Head{evidence.PreIncident, evidence.ExternalAudit, evidence.ExternalPublic} {
		if external.Sequence == evidence.Restored.Sequence && external.StateDigest != evidence.Restored.StateDigest {
			return ReplayPlan{}, ErrFork
		}
	}
	if evidence.ExternalAudit.AuditDigest != evidence.Restored.AuditDigest || evidence.ExternalPublic.PublicDigest != evidence.Restored.PublicDigest {
		return ReplayPlan{}, ErrFork
	}
	return ReplayPlan{FromSequence: evidence.Restored.Sequence + 1, Count: evidence.PendingOutbox, StateDigest: evidence.Restored.StateDigest}, nil
}

func validHead(head Head) bool {
	return head.Epoch > 0 && head.Revision > 0 && head.Sequence > 0 && digestRE.MatchString(head.StateDigest) && digestRE.MatchString(head.AuditDigest) && digestRE.MatchString(head.PublicDigest)
}
