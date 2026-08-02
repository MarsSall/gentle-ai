package sddstatus

import (
	"context"
	"errors"
	"testing"
)

func TestRuntimeLedgerAuthorizesExactlyOneUnmanagedRemediation(t *testing.T) {
	ctx := context.Background()
	repo := initRuntimeLedgerRepo(t)
	store, err := OpenRuntimeStore(ctx, repo, "unmanaged-remediation")
	if err != nil {
		t.Fatal(err)
	}
	store.ReviewDisabled = true
	modeDisabled := true
	store.ReviewDisabledCheck = func() (bool, error) { return modeDisabled, nil }

	started, err := store.Begin(ctx, BeginAttemptRequest{
		RequestID: "failed-begin", WorkUnit: "verification", EvidenceGoal: "independent verification",
		MaxAttempts: 1, MaxChangedLines: 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	failedEvidence := runtimeTestHash('a')
	failed, err := store.Finish(ctx, FinishAttemptRequest{
		ExpectedRevision: started.Revision, RequestID: "failed-finish", Outcome: AttemptFailed,
		EvidenceRevision: failedEvidence, Diagnosis: "substantive validator-admitted failure",
		HarnessDisposition: HarnessReused, CleanupEvidence: "verification cleanup completed",
		ProcessEvidence: "verification process scan found no descendants",
	})
	if err != nil {
		t.Fatal(err)
	}

	request := ResetObjectiveRequest{
		ExpectedRevision: failed.Revision, RequestID: "authorize-remediation", Reason: "maintainer approved one bounded correction",
		Actor: "maintainer", Disposition: ResetDispositionFailedEvidenceRemediation,
		RemediatesEvidenceRevision: failedEvidence, WorkUnit: "correct failed behavior",
		EvidenceGoal: "produce correction evidence", MaxChangedLines: 12,
	}
	request.MaintainerAuthorization = renderUnmanagedRemediationAuthorization(failed.Revision, store.Change, *failed.Objective,
		failed.Attempts[len(failed.Attempts)-1], request.WorkUnit, request.EvidenceGoal, request.MaxChangedLines, request.Actor, request.Reason)
	authorized, err := store.Reset(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if authorized.LastReset == nil || authorized.LastReset.Disposition != ResetDispositionFailedEvidenceRemediation ||
		authorized.LastReset.RemediatesEvidenceRevision != failedEvidence || authorized.LastReset.MaxAttempts != 1 ||
		authorized.LastReset.MaxChangedLines != 12 {
		t.Fatalf("authorization status = %#v", authorized.LastReset)
	}
	replayed, err := store.Reset(ctx, request)
	if err != nil || replayed.Revision != authorized.Revision {
		t.Fatalf("exact replay = %#v, err %v", replayed, err)
	}
	conflict := request
	conflict.MaxChangedLines++
	if _, err := store.Reset(ctx, conflict); !errors.Is(err, ErrRuntimeRequestConflict) {
		t.Fatalf("conflicting replay error = %v", err)
	}

	if _, err := store.Begin(ctx, BeginAttemptRequest{
		ExpectedRevision: authorized.Revision, RequestID: "wrong-scope", WorkUnit: request.WorkUnit,
		EvidenceGoal: request.EvidenceGoal, MaxAttempts: 2, MaxChangedLines: request.MaxChangedLines,
	}); err == nil {
		t.Fatal("authorized remediation accepted max_attempts other than one")
	}
	modeDisabled = false
	if _, err := store.Begin(ctx, BeginAttemptRequest{ExpectedRevision: authorized.Revision, RequestID: "reenabled-begin", WorkUnit: request.WorkUnit, EvidenceGoal: request.EvidenceGoal, MaxAttempts: 1, MaxChangedLines: request.MaxChangedLines}); err == nil {
		t.Fatal("authorized remediation began after review was re-enabled")
	}
	modeDisabled = true
	active, err := store.Begin(ctx, BeginAttemptRequest{
		ExpectedRevision: authorized.Revision, RequestID: "correction-begin", WorkUnit: request.WorkUnit,
		EvidenceGoal: request.EvidenceGoal, MaxAttempts: 1, MaxChangedLines: request.MaxChangedLines,
	})
	if err != nil {
		t.Fatal(err)
	}
	appendRuntimeLedgerFile(t, repo, "bounded unmanaged correction\n")
	finishRequest := FinishAttemptRequest{
		ExpectedRevision: active.Revision, RequestID: "correction-finish", Outcome: AttemptPassed,
		EvidenceRevision: runtimeTestHash('b'), Diagnosis: "bounded correction passed focused checks",
		HarnessDisposition: HarnessReused, CleanupEvidence: "correction cleanup completed",
		ProcessEvidence: "correction process scan found no descendants",
	}
	modeDisabled = false
	if _, err := store.Finish(ctx, finishRequest); err == nil {
		t.Fatal("authorized remediation finished after review was re-enabled")
	}
	modeDisabled = true
	completed, err := store.Finish(ctx, finishRequest)
	if err != nil {
		t.Fatal(err)
	}
	if replayed, replayErr := store.Finish(ctx, finishRequest); replayErr != nil || replayed.Revision != completed.Revision {
		t.Fatalf("finish exact replay = %#v, err %v", replayed, replayErr)
	}
	last := completed.Attempts[len(completed.Attempts)-1]
	if !completed.Complete || last.ChangedLines == 0 || last.RemediatesEvidenceRevision != failedEvidence ||
		completed.LifetimeAttempts != 2 || completed.Objective.MaxAttempts != 1 {
		t.Fatalf("completed remediation = %#v", completed)
	}
	if _, err := store.Reset(ctx, ResetObjectiveRequest{
		ExpectedRevision: completed.Revision, RequestID: "second-reset", Reason: "attempted second correction", Actor: "maintainer",
	}); !errors.Is(err, ErrRuntimeResetNotAllowed) {
		t.Fatalf("consumed authorization reset error = %v", err)
	}
}

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
