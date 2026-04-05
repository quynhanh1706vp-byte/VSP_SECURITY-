package store

import (
	"context"
	"fmt"
	"time"
)

// StoreSchedule — local type, không import scheduler package
type StoreSchedule struct {
	ID        string     `json:"id"`
	TenantID  string     `json:"tenant_id"`
	Name      string     `json:"name"`
	Mode      string     `json:"mode"`
	Profile   string     `json:"profile"`
	Src       string     `json:"src"`
	URL       string     `json:"url"`
	CronExpr  string     `json:"cron"`
	Enabled   bool       `json:"enabled"`
	LastRunAt *time.Time `json:"last_run_at"`
	NextRunAt time.Time  `json:"next_run_at"`
	CreatedAt time.Time  `json:"created_at"`
}

type StoreDriftEvent struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	ScheduleID  string    `json:"schedule_id"`
	PrevPosture string    `json:"prev_posture"`
	NewPosture  string    `json:"new_posture"`
	PrevScore   int       `json:"prev_score"`
	NewScore    int       `json:"new_score"`
	Delta       int       `json:"delta"`
	RID         string    `json:"rid"`
	DetectedAt  time.Time `json:"detected_at"`
}


func (db *DB) ListStoreSchedules(ctx context.Context) ([]StoreSchedule, error) {
	rows, err := db.pool.Query(ctx,
		`SELECT id,tenant_id,name,mode,profile,src,url,cron_expr,
		        enabled,last_run_at,next_run_at,created_at
		 FROM scan_schedules ORDER BY created_at DESC`)
	if err != nil { return nil, err }
	defer rows.Close()
	var list []StoreSchedule
	for rows.Next() {
		var s StoreSchedule
		rows.Scan(&s.ID,&s.TenantID,&s.Name,&s.Mode,&s.Profile,
			&s.Src,&s.URL,&s.CronExpr,&s.Enabled,
			&s.LastRunAt,&s.NextRunAt,&s.CreatedAt) //nolint
		list = append(list, s)
	}
	return list, nil
}

func (db *DB) CreateStoreSchedule(ctx context.Context, s StoreSchedule) (*StoreSchedule, error) {
	row := db.pool.QueryRow(ctx,
		`INSERT INTO scan_schedules (tenant_id,name,mode,profile,src,url,cron_expr,enabled,next_run_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		 RETURNING id,tenant_id,name,mode,profile,src,url,cron_expr,
		           enabled,last_run_at,next_run_at,created_at`,
		s.TenantID,s.Name,s.Mode,s.Profile,s.Src,s.URL,s.CronExpr,s.Enabled,s.NextRunAt)
	var out StoreSchedule
	err := row.Scan(&out.ID,&out.TenantID,&out.Name,&out.Mode,&out.Profile,
		&out.Src,&out.URL,&out.CronExpr,&out.Enabled,
		&out.LastRunAt,&out.NextRunAt,&out.CreatedAt)
	if err != nil { return nil, fmt.Errorf("create schedule: %w", err) }
	return &out, nil
}

func (db *DB) UpdateScheduleRun(ctx context.Context, id string, last, next time.Time) error {
	_, err := db.pool.Exec(ctx,
		`UPDATE scan_schedules SET last_run_at=$2, next_run_at=$3 WHERE id=$1`, id, last, next)
	return err
}

func (db *DB) DeleteSchedule(ctx context.Context, tenantID, id string) error {
	_, err := db.pool.Exec(ctx,
		`DELETE FROM scan_schedules WHERE id=$1 AND tenant_id=$2`, id, tenantID)
	return err
}

func (db *DB) SaveStoreDriftEvent(ctx context.Context, d StoreDriftEvent) error {
	_, err := db.pool.Exec(ctx,
		`INSERT INTO drift_events (tenant_id,schedule_id,prev_posture,new_posture,
		                           prev_score,new_score,delta,rid)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		d.TenantID,d.ScheduleID,d.PrevPosture,d.NewPosture,
		d.PrevScore,d.NewScore,d.Delta,d.RID)
	return err
}

func (db *DB) ListStoreDriftEvents(ctx context.Context, tenantID string, limit int) ([]StoreDriftEvent, error) {
	rows, err := db.pool.Query(ctx,
		`SELECT id,tenant_id,COALESCE(schedule_id::text,''),prev_posture,new_posture,
		        prev_score,new_score,delta,rid,detected_at
		 FROM drift_events WHERE tenant_id=$1 ORDER BY detected_at DESC LIMIT $2`,
		tenantID, limit)
	if err != nil { return nil, err }
	defer rows.Close()
	var list []StoreDriftEvent
	for rows.Next() {
		var d StoreDriftEvent
		rows.Scan(&d.ID,&d.TenantID,&d.ScheduleID,&d.PrevPosture,&d.NewPosture,
			&d.PrevScore,&d.NewScore,&d.Delta,&d.RID,&d.DetectedAt) //nolint
		list = append(list, d)
	}
	return list, nil
}

func (db *DB) UpdateScheduleEnabled(ctx context.Context, tenantID, id string, enabled bool) error {
	_, err := db.pool.Exec(ctx,
		`UPDATE scan_schedules SET enabled=$1 WHERE id=$2 AND tenant_id=$3`,
		enabled, id, tenantID)
	return err
}
