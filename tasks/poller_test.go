package tasks

import (
	"fmt"
	"testing"
	"time"
)

// TestJobProgressMessage tests progress line construction from a job's
// progress object
func TestJobProgressMessage(t *testing.T) {
	tests := []struct {
		name string
		job  map[string]interface{}
		want string
	}{
		{
			name: "description and percent are kept together",
			job: map[string]interface{}{
				"progress": map[string]interface{}{
					"description": "Deploying app",
					"percent":     float64(45),
				},
			},
			want: "Deploying app (45%)",
		},
		{
			name: "description only",
			job: map[string]interface{}{
				"progress": map[string]interface{}{"description": "Pulling images"},
			},
			want: "Pulling images",
		},
		{
			name: "percent only",
			job: map[string]interface{}{
				"progress": map[string]interface{}{"percent": float64(80)},
			},
			want: "Progress: 80%",
		},
		{
			name: "empty description falls back to percent",
			job: map[string]interface{}{
				"progress": map[string]interface{}{"description": "", "percent": float64(10)},
			},
			want: "Progress: 10%",
		},
		{
			name: "no progress object",
			job:  map[string]interface{}{"state": "RUNNING"},
			want: "",
		},
		{
			name: "empty progress object",
			job:  map[string]interface{}{"progress": map[string]interface{}{}},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := jobProgressMessage(tt.job); got != tt.want {
				t.Errorf("jobProgressMessage() = %q, want %q", got, tt.want)
			}
		})
	}
}

// newTestPoller builds a poller backed by a real store with no client, which
// is enough to exercise the poll bookkeeping
func newTestPoller(maxAttempts int) (*Poller, *Task) {
	store := NewTaskStore()
	task := &Task{
		TaskID:        "test-task",
		Status:        TaskStatusWorking,
		OperationType: OperationTypeJob,
		TTL:           3600,
	}
	store.Add(task)
	p := &Poller{store: store, config: PollerConfig{MaxPollAttempts: maxAttempts}}
	return p, task
}

// TestRecordPollFailureKeepsTaskActive verifies transient failures are
// reported without ending the task
func TestRecordPollFailureKeepsTaskActive(t *testing.T) {
	p, task := newTestPoller(0) // unlimited

	for i := 1; i <= 5; i++ {
		p.recordPollFailure(task, fmt.Errorf("connection reset"))
		if task.Status != TaskStatusWorking {
			t.Fatalf("after %d failures status = %v, want still working", i, task.Status)
		}
		if task.PollErrors != i {
			t.Errorf("PollErrors = %d, want %d", task.PollErrors, i)
		}
	}
	if task.LastPollError != "connection reset" {
		t.Errorf("LastPollError = %q, want %q", task.LastPollError, "connection reset")
	}
}

// TestRecordPollFailureGivesUpAtMaxAttempts verifies a task stops reporting
// "working" once its status can no longer be reached
func TestRecordPollFailureGivesUpAtMaxAttempts(t *testing.T) {
	p, task := newTestPoller(3)

	p.recordPollFailure(task, fmt.Errorf("i/o timeout"))
	p.recordPollFailure(task, fmt.Errorf("i/o timeout"))
	if task.Status != TaskStatusWorking {
		t.Fatalf("status = %v after 2 failures, want still working", task.Status)
	}

	p.recordPollFailure(task, fmt.Errorf("i/o timeout"))
	if task.Status != TaskStatusFailed {
		t.Errorf("status = %v after 3 failures, want failed", task.Status)
	}
	if task.StatusMessage == "" {
		t.Error("StatusMessage should explain why polling stopped")
	}
}

// TestRecordPollSuccessClearsFailureState verifies recovery after a transient
// outage
func TestRecordPollSuccessClearsFailureState(t *testing.T) {
	p, task := newTestPoller(0)

	p.recordPollFailure(task, fmt.Errorf("connection reset"))
	p.recordPollFailure(task, fmt.Errorf("connection reset"))

	before := time.Now()
	p.recordPollSuccess(task)

	if task.PollErrors != 0 {
		t.Errorf("PollErrors = %d, want 0 after a successful poll", task.PollErrors)
	}
	if task.LastPollError != "" {
		t.Errorf("LastPollError = %q, want cleared", task.LastPollError)
	}
	if task.LastPolledAt == nil {
		t.Fatal("LastPolledAt should be set after a successful poll")
	}
	if task.LastPolledAt.Before(before) {
		t.Error("LastPolledAt should record the time of the poll")
	}
}

// TestUpdateTaskFromJobCapturesResult verifies a completed job's result is
// retained on the task
func TestUpdateTaskFromJobCapturesResult(t *testing.T) {
	p, task := newTestPoller(0)

	appEntry := map[string]interface{}{"name": "whoami", "state": "RUNNING"}
	p.updateTaskFromJob(task, map[string]interface{}{
		"state":  "SUCCESS",
		"result": appEntry,
	})

	if task.Status != TaskStatusCompleted {
		t.Errorf("status = %v, want completed", task.Status)
	}
	result, ok := task.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("Result = %T, want map", task.Result)
	}
	if result["name"] != "whoami" {
		t.Errorf("Result lost the job payload: %v", result)
	}
}

// TestUpdateTaskFromJobStates tests the job state to task status mapping
func TestUpdateTaskFromJobStates(t *testing.T) {
	tests := []struct {
		state string
		want  TaskStatus
	}{
		{"RUNNING", TaskStatusWorking},
		{"WAITING", TaskStatusWorking},
		{"SUCCESS", TaskStatusCompleted},
		{"FAILED", TaskStatusFailed},
		{"ABORTED", TaskStatusCancelled},
	}

	for _, tt := range tests {
		t.Run(tt.state, func(t *testing.T) {
			p, task := newTestPoller(0)
			p.updateTaskFromJob(task, map[string]interface{}{"state": tt.state})
			if task.Status != tt.want {
				t.Errorf("state %q gave status %v, want %v", tt.state, task.Status, tt.want)
			}
		})
	}
}

// TestUpdateTaskFromJobIgnoresUnknownState verifies an unrecognised state
// leaves the task untouched
func TestUpdateTaskFromJobIgnoresUnknownState(t *testing.T) {
	p, task := newTestPoller(0)
	p.updateTaskFromJob(task, map[string]interface{}{"state": "HOLD"})
	if task.Status != TaskStatusWorking {
		t.Errorf("status = %v, want unchanged working", task.Status)
	}
}

// TestStoreGetReturnsCopy verifies readers cannot observe or mutate the task
// the poller is writing to
func TestStoreGetReturnsCopy(t *testing.T) {
	store := NewTaskStore()
	store.Add(&Task{TaskID: "t1", Status: TaskStatusWorking, TTL: 3600,
		Result: map[string]interface{}{"name": "whoami"}})

	got, err := store.Get("t1")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}

	// Mimic tasks_get dropping the result payload for a caller
	got.Result = nil
	got.Status = TaskStatusFailed

	again, err := store.Get("t1")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if again.Result == nil {
		t.Error("mutating a returned task cleared the stored result")
	}
	if again.Status != TaskStatusWorking {
		t.Errorf("stored status = %v, want unchanged working", again.Status)
	}
}
