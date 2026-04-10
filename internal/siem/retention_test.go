package siem

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDefaultRetention(t *testing.T) {
	cfg := DefaultRetention()
	assert.Equal(t, 90, cfg.LogEventsDays)
	assert.Equal(t, 365, cfg.IncidentsDays)
	assert.Equal(t, 180, cfg.PlaybookRunsDays)
	assert.Equal(t, 30, cfg.IOCExpiredDays)
}

func TestRetentionConfig_AllPositive(t *testing.T) {
	cfg := RetentionConfig{
		LogEventsDays:    7,
		IncidentsDays:    30,
		PlaybookRunsDays: 14,
		IOCExpiredDays:   3,
	}
	assert.Equal(t, 7, cfg.LogEventsDays)
	assert.Equal(t, 30, cfg.IncidentsDays)
	assert.Equal(t, 14, cfg.PlaybookRunsDays)
	assert.Equal(t, 3, cfg.IOCExpiredDays)
}

func TestRetentionConfig_ZeroValues(t *testing.T) {
	cfg := RetentionConfig{}
	assert.Equal(t, 0, cfg.LogEventsDays)
	assert.Equal(t, 0, cfg.IncidentsDays)
}
