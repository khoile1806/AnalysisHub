// Package updater provides a single registry + scheduler for every periodically
// self-updating data source and tool in the system (nuclei templates, the
// retire.js DB, the CISA KEV catalog, threat-intel feeds, …). Each component
// registers a Spec once; the Manager runs it on start (staggered) and on its
// interval, tracks status, and lets an operator trigger a refresh on demand.
package updater

import (
	"context"
	"log"
	"sync"
	"time"
)

// UpdateFunc performs one refresh. It should honour ctx (which carries a per-run
// timeout) and return a non-nil error only on genuine failure.
type UpdateFunc func(ctx context.Context) error

// Spec describes one auto-updating component.
type Spec struct {
	Name        string        // stable id, e.g. "nuclei-templates"
	Description string        // human label
	Category    string        // "cli-tool" | "embedded-db" | "feed" | "catalog"
	Interval    time.Duration // refresh cadence
	Timeout     time.Duration // per-run wall-clock budget (default 15m)
	RunOnStart  bool          // run once shortly after boot
	StartDelay  time.Duration // stagger from boot before the first run
	MaxRetries  int           // auto-retry attempts after a failed run (0 = default)
	Fn          UpdateFunc
}

// Status is the observable state of one updater, exposed to the admin UI.
type Status struct {
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Category    string     `json:"category"`
	IntervalSec int64      `json:"interval_seconds"`
	Running     bool       `json:"running"`
	Runs        int        `json:"runs"`
	LastRun     *time.Time `json:"last_run,omitempty"`
	LastSuccess bool       `json:"last_success"`
	LastError   string     `json:"last_error,omitempty"`
	LastMessage string     `json:"last_message,omitempty"`
	LastDurMs   int64      `json:"last_duration_ms"`
	NextRun     *time.Time `json:"next_run,omitempty"`

	// Self-healing: after a failed run the manager auto-retries with backoff
	// instead of waiting the full interval. Attempt is the consecutive failure
	// count (0 when healthy); NextRetry is when the next auto-retry fires.
	Attempt   int        `json:"attempt"`
	NextRetry *time.Time `json:"next_retry,omitempty"`
}

// defaultMaxRetries is the number of backoff retries after a failed run before
// the manager gives up until the next scheduled interval.
const defaultMaxRetries = 4

type entry struct {
	spec    Spec
	status  Status
	trigger chan struct{}
}

// Manager owns the registry and per-component scheduling loops.
type Manager struct {
	mu      sync.Mutex
	entries map[string]*entry
	order   []string
	started bool
	now     func() time.Time

	// onResult, when set, is invoked after every run so the app layer can persist
	// a health event. Kept as a hook so this package needs no DB import.
	onResult func(name string, success bool, attempt int, detail string)
}

// OnResult registers a callback invoked after each component run (success or
// failure). Set once before Start.
func (m *Manager) OnResult(fn func(name string, success bool, attempt int, detail string)) {
	m.mu.Lock()
	m.onResult = fn
	m.mu.Unlock()
}

// resultMsg lets an UpdateFunc report a short human message via a sentinel error
// wrapper; most updaters just return nil/err and the manager derives the message.
// (Kept simple: updaters log their own detail.)

// Default is the process-wide updater registry. main.go registers the concrete
// components on it; the API handler reads its status. Kept as a singleton so the
// API layer needs no import of the app packages that supply the update functions
// (which would create an import cycle).
var Default = NewManager()

// NewManager returns an empty registry.
func NewManager() *Manager {
	return &Manager{entries: map[string]*entry{}, now: time.Now}
}

// Register adds a component. Must be called before Start. Duplicate names are
// ignored (first wins) so wiring is idempotent.
func (m *Manager) Register(s Spec) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.entries[s.Name]; exists {
		return
	}
	if s.Timeout <= 0 {
		s.Timeout = 15 * time.Minute
	}
	m.entries[s.Name] = &entry{
		spec:    s,
		trigger: make(chan struct{}, 1),
		status: Status{
			Name: s.Name, Description: s.Description, Category: s.Category,
			IntervalSec: int64(s.Interval / time.Second),
		},
	}
	m.order = append(m.order, s.Name)
}

// Start launches one scheduling goroutine per registered component. It is safe to
// call once; subsequent calls are no-ops.
func (m *Manager) Start(ctx context.Context) {
	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return
	}
	m.started = true
	names := append([]string(nil), m.order...)
	m.mu.Unlock()

	for i, name := range names {
		// Stagger boot runs so a dozen updaters don't all hit the network at once.
		delay := m.entries[name].spec.StartDelay
		if delay <= 0 {
			delay = time.Duration(15+i*20) * time.Second
		}
		go m.loop(ctx, name, delay)
	}
	log.Printf("[updater] scheduler started for %d component(s)", len(names))
}

func (m *Manager) loop(ctx context.Context, name string, startDelay time.Duration) {
	e := m.entries[name]

	t := time.NewTicker(e.spec.Interval)
	defer t.Stop()
	m.setNextRun(name, m.now().Add(e.spec.Interval))

	// The boot run and the periodic runs share one select so a manual trigger is
	// always handled promptly — even while the staggered start delay is pending.
	var startCh <-chan time.Time
	if e.spec.RunOnStart {
		startCh = time.After(startDelay)
	}
	var retryCh <-chan time.Time // fires when a backoff auto-retry is due

	// freshRun starts a new cycle (boot / interval / manual): reset the retry
	// counter, run, and arm a retry if it failed.
	freshRun := func() {
		m.clearRetry(name)
		if d, ok := m.runCycle(ctx, name); ok {
			retryCh = time.After(d)
		} else {
			retryCh = nil
		}
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-startCh:
			startCh = nil
			freshRun()
		case <-t.C:
			freshRun()
			m.setNextRun(name, m.now().Add(e.spec.Interval))
		case <-e.trigger:
			freshRun()
			m.setNextRun(name, m.now().Add(e.spec.Interval))
		case <-retryCh:
			// A backoff retry — do NOT reset the attempt counter.
			retryCh = nil
			if d, ok := m.runCycle(ctx, name); ok {
				retryCh = time.After(d)
			}
		}
	}
}

// runCycle executes one run and, on failure, schedules the next backoff retry.
// Returns (delay, true) when a retry should be armed, or (0, false) on success
// or once retries are exhausted.
func (m *Manager) runCycle(ctx context.Context, name string) (time.Duration, bool) {
	if m.execute(ctx, name) { // true == failed
		return m.scheduleRetry(name)
	}
	m.clearRetry(name)
	return 0, false
}

// scheduleRetry bumps the failure counter and returns the backoff delay, or
// ok=false once MaxRetries is reached (the component then waits for its next
// scheduled interval).
func (m *Manager) scheduleRetry(name string) (time.Duration, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e := m.entries[name]
	max := e.spec.MaxRetries
	if max <= 0 {
		max = defaultMaxRetries
	}
	if e.status.Attempt >= max {
		e.status.NextRetry = nil
		return 0, false
	}
	e.status.Attempt++
	d := backoffFor(e.status.Attempt)
	nt := m.now().Add(d)
	e.status.NextRetry = &nt
	log.Printf("[updater] %s auto-retry %d/%d in %s", name, e.status.Attempt, max, d)
	return d, true
}

// clearRetry resets the retry state (called on success and at the start of each
// fresh cycle).
func (m *Manager) clearRetry(name string) {
	m.mu.Lock()
	if e, ok := m.entries[name]; ok {
		e.status.Attempt = 0
		e.status.NextRetry = nil
	}
	m.mu.Unlock()
}

// backoffFor returns the delay before retry attempt n: 1m, 3m, 9m, 27m … capped.
func backoffFor(attempt int) time.Duration {
	d := time.Minute
	for i := 1; i < attempt; i++ {
		d *= 3
	}
	if d > 30*time.Minute {
		d = 30 * time.Minute
	}
	return d
}

func (m *Manager) execute(ctx context.Context, name string) (failed bool) {
	e := m.entries[name]

	m.mu.Lock()
	if e.status.Running {
		m.mu.Unlock()
		return false // a run is already in flight (e.g. manual trigger during a scheduled run)
	}
	e.status.Running = true
	m.mu.Unlock()

	start := m.now()
	rctx, cancel := context.WithTimeout(ctx, e.spec.Timeout)
	err := safeRun(rctx, e.spec.Fn)
	cancel()
	dur := m.now().Sub(start)

	m.mu.Lock()
	e.status.Running = false
	e.status.Runs++
	ended := m.now()
	e.status.LastRun = &ended
	e.status.LastDurMs = dur.Milliseconds()
	if err != nil {
		e.status.LastSuccess = false
		e.status.LastError = err.Error()
		log.Printf("[updater] %s FAILED after %s: %v", name, dur.Round(time.Millisecond), err)
	} else {
		e.status.LastSuccess = true
		e.status.LastError = ""
		log.Printf("[updater] %s ok in %s", name, dur.Round(time.Millisecond))
	}
	hook := m.onResult
	attempt := e.status.Attempt
	m.mu.Unlock()

	if hook != nil {
		detail := ""
		if err != nil {
			detail = err.Error()
		}
		hook(name, err == nil, attempt, detail)
	}
	return err != nil
}

// safeRun runs fn, converting a panic into an error so one bad updater can't crash
// the process.
func safeRun(ctx context.Context, fn UpdateFunc) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = &panicError{v: r}
		}
	}()
	return fn(ctx)
}

type panicError struct{ v any }

func (p *panicError) Error() string { return "panic: " + toStr(p.v) }

func toStr(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	if e, ok := v.(error); ok {
		return e.Error()
	}
	return "unknown"
}

func (m *Manager) setNextRun(name string, t time.Time) {
	m.mu.Lock()
	if e, ok := m.entries[name]; ok {
		nt := t
		e.status.NextRun = &nt
	}
	m.mu.Unlock()
}

// RunNow signals a component to refresh as soon as possible. Non-blocking; returns
// an error only when the name is unknown.
func (m *Manager) RunNow(name string) error {
	m.mu.Lock()
	e, ok := m.entries[name]
	m.mu.Unlock()
	if !ok {
		return errUnknown(name)
	}
	select {
	case e.trigger <- struct{}{}:
	default: // a run is already queued
	}
	return nil
}

// Statuses returns a snapshot of every component's status, in registration order.
func (m *Manager) Statuses() []Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Status, 0, len(m.order))
	for _, name := range m.order {
		out = append(out, m.entries[name].status)
	}
	return out
}

type errUnknown string

func (e errUnknown) Error() string { return "unknown updater: " + string(e) }
