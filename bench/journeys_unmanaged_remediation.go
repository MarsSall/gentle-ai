package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

const (
	unmanagedFailedReport = "```yaml\n" +
		"schema: gentle-ai.verify-result/v1\n" +
		"evidence_revision: " + sddFailedEvidence + "\n" +
		"verdict: fail\nblockers: 1\ncritical_findings: 0\nrequirements: 1/1\nscenarios: 1/1\n" +
		"test_command: go test ./internal/example\ntest_exit_code: 0\n" +
		"test_output_hash: sha256:2222222222222222222222222222222222222222222222222222222222222222\n" +
		"build_command: go test ./cmd/gentle-ai\nbuild_exit_code: 0\n" +
		"build_output_hash: sha256:3333333333333333333333333333333333333333333333333333333333333333\n```\n"
	unmanagedPassedEvidence = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	unmanagedPassedReport   = "```yaml\n" +
		"schema: gentle-ai.verify-result/v1\n" +
		"evidence_revision: " + unmanagedPassedEvidence + "\n" +
		"verdict: pass\nblockers: 0\ncritical_findings: 0\nrequirements: 1/1\nscenarios: 1/1\n" +
		"test_command: go test ./internal/example\ntest_exit_code: 0\n" +
		"test_output_hash: sha256:4444444444444444444444444444444444444444444444444444444444444444\n" +
		"build_command: go test ./cmd/gentle-ai\nbuild_exit_code: 0\n" +
		"build_output_hash: sha256:5555555555555555555555555555555555555555555555555555555555555555\n```\n"
	unmanagedWorkUnit        = "correct admitted failed verification"
	unmanagedEvidenceGoal    = "produce bounded correction evidence"
	unmanagedMaxChangedLines = 20
	unmanagedActor           = "bench-maintainer"
	unmanagedReason          = "authorize one bounded unmanaged correction"
)

type unmanagedRuntimeStatus struct {
	Revision  string `json:"revision"`
	Objective *struct {
		ID         string `json:"id"`
		Generation int    `json:"generation"`
	} `json:"objective"`
	ActiveAttempt any `json:"active_attempt"`
	Attempts      []struct {
		ObjectiveID             string `json:"objective_id"`
		ObjectiveGeneration     int    `json:"objective_generation"`
		Outcome                 string `json:"outcome"`
		EvidenceRevision        string `json:"evidence_revision"`
		FinishCandidateIdentity string `json:"finish_candidate_identity"`
		FinishCandidateTree     string `json:"finish_candidate_tree"`
	} `json:"attempts"`
	DecisionRequired bool   `json:"decision_required"`
	Complete         bool   `json:"complete"`
	NextAction       string `json:"next_action"`
}

var unmanagedResetCapability = &Capability{
	Verb: []string{"sdd-attempt", "reset"},
	Probe: []string{"sdd-attempt", "reset", "--expected-revision=" + sddFailedEvidence, "--request-id=probe",
		"--reason=probe", "--actor=probe", "--disposition=failed-evidence-remediation",
		"--remediates-evidence-revision=" + sddFailedEvidence, "--work-unit=probe", "--evidence-goal=probe",
		"--max-changed-lines=1", "--maintainer-authorization=probe"},
}

var sddVerifyValidateCapability = &Capability{
	Verb:  []string{"sdd-verify-validate"},
	Probe: []string{"sdd-verify-validate", "--input=missing", "--requirements=1", "--scenarios=1"},
}

func unmanagedReportFixture(key, report string) func(*Sandbox) error {
	return func(sandbox *Sandbox) error {
		path, err := writeScratch(sandbox, key+".md", []byte(report))
		if err == nil {
			sandbox.Scratch[key] = path
		}
		return err
	}
}

func unmanagedValidateArgs(key string) func(*Sandbox) ([]string, error) {
	return func(sandbox *Sandbox) ([]string, error) {
		return []string{"sdd-verify-validate", "--input", sandbox.Scratch[key], "--requirements", "1", "--scenarios", "1"}, nil
	}
}

func requireAdmittedVerification(verdict, evidence string) func(*Sandbox, Observation) error {
	return func(_ *Sandbox, observation Observation) error {
		var admission struct {
			Valid            bool   `json:"valid"`
			Verdict          string `json:"verdict"`
			EvidenceRevision string `json:"evidence_revision"`
		}
		if err := json.Unmarshal([]byte(strings.TrimSpace(observation.Stdout)), &admission); err != nil {
			return err
		}
		if !admission.Valid || admission.Verdict != verdict || admission.EvidenceRevision != evidence {
			return fmt.Errorf("verification admission = %+v, want valid %s %s", admission, verdict, evidence)
		}
		return nil
	}
}

func persistUnmanagedReport(report string) func(*Sandbox) error {
	return func(sandbox *Sandbox) error {
		return sandbox.write(filepath.Join(sddChangeRoot(sandbox), "verify-report.md"), report)
	}
}

func readUnmanagedRuntime(r *journeyRun) (unmanagedRuntimeStatus, error) {
	observation := r.run([]string{"sdd-attempt", "status", "--cwd", r.sandbox.Repo, "--change", sddChange}, false)
	var status unmanagedRuntimeStatus
	err := json.Unmarshal([]byte(strings.TrimSpace(observation.Stdout)), &status)
	return status, err
}

func unmanagedFailVerification(r *journeyRun) error {
	status, err := readUnmanagedRuntime(r)
	if err != nil {
		return err
	}
	r.run(sddAttemptArgs(r, "begin", status.Revision, "unmanaged-verify-begin",
		"--work-unit", "independent verification", "--evidence-goal", "admit substantive failure",
		"--max-attempts", "1", "--max-changed-lines", "20"), false)
	status, err = readUnmanagedRuntime(r)
	if err != nil {
		return err
	}
	r.run(sddAttemptArgs(r, "finish", status.Revision, "unmanaged-verify-finish",
		append([]string{"--outcome", "failed", "--evidence-revision", sddFailedEvidence}, sddTerminalEvidence...)...), false)
	status, err = readUnmanagedRuntime(r)
	if err != nil {
		return err
	}
	if !status.DecisionRequired || len(status.Attempts) != 1 || status.Attempts[0].Outcome != "failed" {
		return fmt.Errorf("failed verification runtime = %+v", status)
	}
	return nil
}

func proveNoReviewAuthority(r *journeyRun) error {
	observation := r.run(productArgsFor(r, "review", "status"), false)
	var inventory waveInventory
	if err := json.Unmarshal([]byte(strings.TrimSpace(observation.Stdout)), &inventory); err != nil {
		return err
	}
	if !inventory.Complete || !inventory.Authoritative || len(inventory.Entries) != 0 {
		return fmt.Errorf("unmanaged correction created review authority: %+v", inventory)
	}
	return nil
}

func unmanagedAuthorization(status unmanagedRuntimeStatus) (string, error) {
	if status.Objective == nil || len(status.Attempts) != 1 {
		return "", fmt.Errorf("authorization source runtime = %+v", status)
	}
	failed := status.Attempts[0]
	return strings.Join([]string{
		"gentle-ai.sdd-unmanaged-remediation-authorization/v1",
		"delivery=disabled/unmanaged",
		"runtime_revision=" + status.Revision,
		"change=" + sddChange,
		"objective_id=" + status.Objective.ID,
		fmt.Sprintf("objective_generation=%d", status.Objective.Generation),
		"failed_evidence_revision=" + failed.EvidenceRevision,
		"failed_candidate_identity=" + failed.FinishCandidateIdentity,
		"failed_candidate_tree=" + failed.FinishCandidateTree,
		"work_unit=" + unmanagedWorkUnit,
		"evidence_goal=" + unmanagedEvidenceGoal,
		"max_attempts=1",
		fmt.Sprintf("max_changed_lines=%d", unmanagedMaxChangedLines),
		"actor=" + unmanagedActor,
		"reason=" + unmanagedReason,
	}, "\n"), nil
}

func authorizeUnmanagedCorrection(r *journeyRun) error {
	status, err := readUnmanagedRuntime(r)
	if err != nil {
		return err
	}
	authorization, err := unmanagedAuthorization(status)
	if err != nil {
		return err
	}
	r.sandbox.Scratch["unmanaged-reset-revision"] = status.Revision
	r.sandbox.Scratch["unmanaged-authorization"] = authorization
	args := sddAttemptArgs(r, "reset", status.Revision, "unmanaged-authorize",
		"--reason", unmanagedReason, "--actor", unmanagedActor,
		"--disposition", "failed-evidence-remediation", "--remediates-evidence-revision", sddFailedEvidence,
		"--work-unit", unmanagedWorkUnit, "--evidence-goal", unmanagedEvidenceGoal,
		"--max-changed-lines", fmt.Sprint(unmanagedMaxChangedLines), "--maintainer-authorization", authorization)
	observation := r.run(args, false)
	if observation.ExitCode != 0 || strings.Contains(observation.Stdout+observation.Stderr, authorization) {
		return errors.New("authorization failed or raw authorization was echoed")
	}
	return nil
}

func completeUnmanagedCorrection(r *journeyRun) error {
	status, err := readUnmanagedRuntime(r)
	if err != nil || status.NextAction != "begin" {
		return fmt.Errorf("authorized runtime = %+v: %v", status, err)
	}
	r.run(sddAttemptArgs(r, "begin", status.Revision, "unmanaged-correction-begin",
		"--work-unit", unmanagedWorkUnit, "--evidence-goal", unmanagedEvidenceGoal,
		"--max-attempts", "1", "--max-changed-lines", fmt.Sprint(unmanagedMaxChangedLines)), false)
	if err := sddBoundedCorrection(r.sandbox); err != nil {
		return err
	}
	status, err = readUnmanagedRuntime(r)
	if err != nil {
		return err
	}
	r.run(sddAttemptArgs(r, "finish", status.Revision, "unmanaged-correction-finish",
		append([]string{"--outcome", "passed", "--evidence-revision", sddCorrectedEvidence}, sddTerminalEvidence...)...), false)
	status, err = readUnmanagedRuntime(r)
	if err != nil || !status.Complete || len(status.Attempts) != 2 {
		return fmt.Errorf("completed correction runtime = %+v: %v", status, err)
	}
	return nil
}

func replayUnmanagedAuthorization(r *journeyRun) error {
	before, err := readUnmanagedRuntime(r)
	if err != nil {
		return err
	}
	args := sddAttemptArgs(r, "reset", r.sandbox.Scratch["unmanaged-reset-revision"], "unmanaged-authorize",
		"--reason", unmanagedReason, "--actor", unmanagedActor,
		"--disposition", "failed-evidence-remediation", "--remediates-evidence-revision", sddFailedEvidence,
		"--work-unit", unmanagedWorkUnit, "--evidence-goal", unmanagedEvidenceGoal,
		"--max-changed-lines", fmt.Sprint(unmanagedMaxChangedLines),
		"--maintainer-authorization", r.sandbox.Scratch["unmanaged-authorization"])
	observation := r.run(args, false)
	var after unmanagedRuntimeStatus
	if err := json.Unmarshal([]byte(strings.TrimSpace(observation.Stdout)), &after); err != nil {
		return err
	}
	if observation.ExitCode != 0 || after.Revision != before.Revision || len(after.Attempts) != len(before.Attempts) || after.ActiveAttempt != nil {
		return fmt.Errorf("authorization replay created another correction: before=%+v after=%+v", before, after)
	}
	return nil
}

func unmanagedRemediationJourneys() []Journey {
	return []Journey{{
		ID:     "j52-disabled-failed-verification-unmanaged-remediation",
		Title:  "Disabled substantive verification failure receives one bounded correction, then fresh verification",
		Source: "issue #2182 accepted unmanaged-remediation design",
		Steps: []Step{
			{Name: "fixture: complete OpenSpec change without verification", Fixture: sddPlanningArtifacts("")},
			{Name: "mode disable", Requires: modeCapability, Args: productArgs("review", "mode", "disable", "--json")},
			{Name: "fixture: failed verification report", Fixture: unmanagedReportFixture("unmanaged-fail", unmanagedFailedReport)},
			{Name: "validator admits substantive FAIL", Requires: sddVerifyValidateCapability, Args: unmanagedValidateArgs("unmanaged-fail"), After: requireAdmittedVerification("fail", sddFailedEvidence)},
			{Name: "persist admitted FAIL", Fixture: persistUnmanagedReport(unmanagedFailedReport)},
			{Name: "terminal failed runtime verification", Requires: sddAttemptBeginCapability, Composite: unmanagedFailVerification},
			{Name: "status exposes one unmanaged remediation", Requires: sddStatusCapability, Args: productArgs("sdd-status", sddChange, "--json"), After: sddStatusAssertion("unmanaged remediation routing", func(status sddStatusV1) error {
				if status.NextRecommended != "remediate" || !status.RemediationState.Required || status.RemediationState.FailedEvidenceRevision != sddFailedEvidence || status.Dependencies.Archive != "blocked" || status.ReviewGate == nil || status.ReviewGate.Delivery != deliveryDisabledUnmanaged || status.ReviewGate.Result == "allow" {
					return fmt.Errorf("unexpected unmanaged remediation status: %+v", status)
				}
				return nil
			})},
			{Name: "prove no review authority before correction", Requires: statusCapability, Composite: proveNoReviewAuthority},
			{Name: "authorize exactly one bounded correction", Requires: unmanagedResetCapability, Composite: authorizeUnmanagedCorrection},
			{Name: "complete the bounded correction", Requires: sddAttemptFinishCapability, Composite: completeUnmanagedCorrection},
			{Name: "status routes only to fresh verification", Requires: sddStatusCapability, Args: productArgs("sdd-status", sddChange, "--json"), After: sddStatusAssertion("post-correction routing", func(status sddStatusV1) error {
				if status.NextRecommended != "verify" || status.Dependencies.Verify != "ready" || status.Dependencies.Archive != "blocked" {
					return fmt.Errorf("post-correction status = %+v", status)
				}
				return nil
			})},
			{Name: "prove correction created no review authority", Requires: statusCapability, Composite: proveNoReviewAuthority},
			{Name: "fixture: fresh verification report", Fixture: unmanagedReportFixture("unmanaged-pass", unmanagedPassedReport)},
			{Name: "validator admits fresh independent PASS", Requires: sddVerifyValidateCapability, Args: unmanagedValidateArgs("unmanaged-pass"), After: requireAdmittedVerification("pass", unmanagedPassedEvidence)},
			{Name: "persist fresh independent PASS", Fixture: persistUnmanagedReport(unmanagedPassedReport)},
			{Name: "archive is disabled/unmanaged without approval", Requires: sddStatusCapability, Args: productArgs("sdd-status", sddChange, "--json"), After: sddStatusAssertion("unmanaged archive routing", func(status sddStatusV1) error {
				if status.NextRecommended != "archive" || status.Dependencies.Archive == "blocked" || status.ReviewGate == nil || status.ReviewGate.Delivery != deliveryDisabledUnmanaged || status.ReviewGate.Result == "allow" {
					return fmt.Errorf("archive status = %+v", status)
				}
				return nil
			})},
			{Name: "exact authorization replay cannot create a second correction", Requires: unmanagedResetCapability, Composite: replayUnmanagedAuthorization},
		},
	}}
}
