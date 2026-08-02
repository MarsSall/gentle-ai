package sddstatus

import (
	"context"
	"errors"
	"testing"
)

func TestRuntimeLedgerUnmanagedRemediationFailsClosed(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*RuntimeStore, *ResetObjectiveRequest)
	}{
		{name: "enabled review", mutate: func(store *RuntimeStore, _ *ResetObjectiveRequest) { store.ReviewDisabled = false }},
		{name: "unreadable review mode", mutate: func(store *RuntimeStore, _ *ResetObjectiveRequest) {
			store.ReviewDisabledCheck = func() (bool, error) { return false, errors.New("unreadable mode") }
		}},
		{name: "foreign evidence", mutate: func(_ *RuntimeStore, request *ResetObjectiveRequest) {
			request.RemediatesEvidenceRevision = runtimeTestHash('f')
		}},
		{name: "wrong exact binding", mutate: func(_ *RuntimeStore, request *ResetObjectiveRequest) {
			request.MaintainerAuthorization = "wrong-binding"
		}},
		{name: "zero line ceiling", mutate: func(_ *RuntimeStore, request *ResetObjectiveRequest) { request.MaxChangedLines = 0 }},
		{name: "missing authorization", mutate: func(_ *RuntimeStore, request *ResetObjectiveRequest) { request.MaintainerAuthorization = "" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			repo := initRuntimeLedgerRepo(t)
			store, err := OpenRuntimeStore(ctx, repo, "guarded-remediation")
			if err != nil {
				t.Fatal(err)
			}
			store.ReviewDisabled = true
			started, err := store.Begin(ctx, BeginAttemptRequest{RequestID: "begin", WorkUnit: "verify", EvidenceGoal: "verify", MaxAttempts: 1, MaxChangedLines: 10})
			if err != nil {
				t.Fatal(err)
			}
			evidence := runtimeTestHash('c')
			failed, err := store.Finish(ctx, FinishAttemptRequest{ExpectedRevision: started.Revision, RequestID: "finish", Outcome: AttemptFailed, EvidenceRevision: evidence, Diagnosis: "substantive failure", HarnessDisposition: HarnessReused, CleanupEvidence: "cleanup complete", ProcessEvidence: "process scan complete"})
			if err != nil {
				t.Fatal(err)
			}
			request := ResetObjectiveRequest{ExpectedRevision: failed.Revision, RequestID: "authorize", Reason: "maintainer authorized correction", Actor: "maintainer", Disposition: ResetDispositionFailedEvidenceRemediation, RemediatesEvidenceRevision: evidence, WorkUnit: "correction", EvidenceGoal: "correct evidence", MaxChangedLines: 10}
			request.MaintainerAuthorization = renderUnmanagedRemediationAuthorization(failed.Revision, store.Change, *failed.Objective,
				failed.Attempts[len(failed.Attempts)-1], request.WorkUnit, request.EvidenceGoal, request.MaxChangedLines, request.Actor, request.Reason)
			tt.mutate(&store, &request)
			if _, err := store.Reset(ctx, request); err == nil {
				t.Fatal("invalid unmanaged remediation authorization succeeded")
			}
			status, err := store.Status()
			if err != nil || status.Revision != failed.Revision {
				t.Fatalf("denial mutated ledger: %#v, err %v", status, err)
			}
		})
	}
}
