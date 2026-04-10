package scheduler

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/vsp/platform/internal/store"
)

type EnqueueFunc func(rid, tenantID, mode, profile, src, url string)

type Engine struct {
	mu        sync.Mutex
	schedules []store.StoreSchedule
	db        *store.DB
	enqueue   EnqueueFunc
	done      chan struct{}
}

func New(db *store.DB, enqueue EnqueueFunc) *Engine {
	return &Engine{db: db, enqueue: enqueue, done: make(chan struct{})}
}

func (e *Engine) Start(ctx context.Context) {
	e.loadSchedules(ctx)
	go e.loop(ctx)
	log.Info().Msg("scheduler: started")
}

func (e *Engine) Stop() {
	select {
	case <-e.done:
	default:
		close(e.done)
	}
}

func (e *Engine) loop(ctx context.Context) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-e.done:
			return
		case <-ticker.C:
			e.tick(ctx)
		}
	}
}

func (e *Engine) tick(ctx context.Context) {
	e.loadSchedules(ctx)
	now := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()
	for i, s := range e.schedules {
		if !s.Enabled { continue }
		if now.Before(s.NextRunAt) { continue }
		log.Info().Str("schedule", s.Name).Str("mode", s.Mode).Msg("scheduler: firing")
		rid := fmt.Sprintf("RID_SCHED_%s_%d", now.Format("20060102_150405"), i)
		e.enqueue(rid, s.TenantID, s.Mode, s.Profile, s.Src, s.URL)
		next := nextRun(s.CronExpr, now)
		e.schedules[i].LastRunAt = &now
		e.schedules[i].NextRunAt = next
		e.db.UpdateScheduleRun(ctx, s.ID, now, next) //nolint:errcheck
		go e.checkDrift(ctx, s, rid)
	}
}

func (e *Engine) checkDrift(ctx context.Context, s store.StoreSchedule, rid string) {
	// Respect context cancellation during sleep
	select {
	case <-ctx.Done():
		return
	case <-time.After(5 * time.Minute):
	}
	runs, err := e.db.ListRuns(ctx, s.TenantID, 2, 0)
	if err != nil || len(runs) < 2 { return }
	postureScore := map[string]int{"A": 100, "B": 85, "C": 70, "D": 55, "F": 20}
	if runs[1].Posture == runs[0].Posture { return }
	delta := postureScore[runs[0].Posture] - postureScore[runs[1].Posture]
	log.Warn().Int("delta", delta).Msg("scheduler: drift detected")
	e.db.SaveStoreDriftEvent(ctx, store.StoreDriftEvent{ //nolint:errcheck
		TenantID:    s.TenantID,
		ScheduleID:  s.ID,
		PrevPosture: runs[1].Posture,
		NewPosture:  runs[0].Posture,
		PrevScore:   postureScore[runs[1].Posture],
		NewScore:    postureScore[runs[0].Posture],
		Delta:       delta,
		RID:         rid,
		DetectedAt:  time.Now(),
	})
}

func (e *Engine) loadSchedules(ctx context.Context) {
	scheds, _ := e.db.ListStoreSchedules(ctx)
	e.mu.Lock()
	e.schedules = scheds
	e.mu.Unlock()
}

func (e *Engine) AddSchedule(ctx context.Context, s store.StoreSchedule) (*store.StoreSchedule, error) {
	s.NextRunAt = nextRun(s.CronExpr, time.Now())
	return e.db.CreateStoreSchedule(ctx, s)
}

func (e *Engine) ListSchedules(_ context.Context) []store.StoreSchedule {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.schedules
}

func (e *Engine) TriggerNow(_ context.Context, s store.StoreSchedule) {
	rid := fmt.Sprintf("RID_MANUAL_%s", time.Now().Format("20060102_150405"))
	e.enqueue(rid, s.TenantID, s.Mode, s.Profile, s.Src, s.URL)
	log.Info().Str("schedule", s.Name).Str("rid", rid).Msg("scheduler: manual trigger")
}

func nextRun(expr string, from time.Time) time.Time {
	var parts [5]string
	fmt.Sscanf(expr, "%s %s %s %s %s", &parts[0], &parts[1], &parts[2], &parts[3], &parts[4])
	if parts[0] == "*/30" { return from.Add(30 * time.Minute) }
	if parts[0] == "*/15" { return from.Add(15 * time.Minute) }
	if parts[0] == "*/5"  { return from.Add(5 * time.Minute) }
	if parts[0] == "*"    { return from.Add(time.Minute) }
	var min, hour int
	fmt.Sscanf(parts[0], "%d", &min)
	if parts[1] == "*/6"  { return from.Add(6 * time.Hour) }
	if parts[1] == "*/12" { return from.Add(12 * time.Hour) }
	if parts[1] == "*"    { return from.Add(time.Hour) }
	fmt.Sscanf(parts[1], "%d", &hour)
	next := time.Date(from.Year(), from.Month(), from.Day(), hour, min, 0, 0, from.Location())
	if !next.After(from) { next = next.Add(24 * time.Hour) }
	return next
}
