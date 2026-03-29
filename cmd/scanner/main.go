package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"strings"

	"github.com/hibiken/asynq"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"github.com/vsp/platform/internal/pipeline"
	"github.com/vsp/platform/internal/store"
)

func main() {
	viper.SetDefault("redis.addr", "localhost:6379")
	viper.SetDefault("database.url", "postgres://vsp:vsp@localhost:5432/vsp_go")
	viper.SetDefault("scanner.concurrency", 3)
	viper.SetDefault("log.level", "info")
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./config")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.BindEnv("database.url", "DATABASE_URL")
	viper.BindEnv("redis.addr", "REDIS_ADDR")
	viper.BindEnv("redis.password", "REDIS_PASSWORD")
	viper.ReadInConfig()

	level, _ := zerolog.ParseLevel(viper.GetString("log.level"))
	zerolog.SetGlobalLevel(level)
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339})

	ctx := context.Background()
	db, err := store.New(ctx, viper.GetString("database.url"))
	if err != nil {
		log.Fatal().Err(err).Msg("db connect failed")
	}
	defer db.Close()

	handler := pipeline.NewScanHandler(db)

	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" { redisAddr = viper.GetString("redis.addr") }
	redisPass := os.Getenv("REDIS_PASSWORD")
	if redisPass == "" { redisPass = viper.GetString("redis.password") }
	srv := asynq.NewServer(
		asynq.RedisClientOpt{Addr: redisAddr, Password: redisPass},
		asynq.Config{
			Concurrency: viper.GetInt("scanner.concurrency"),
			Queues:      map[string]int{"critical": 6, "default": 3, "low": 1},
			ErrorHandler: asynq.ErrorHandlerFunc(func(ctx context.Context, task *asynq.Task, err error) {
				log.Error().Err(err).Str("task", task.Type()).Msg("task failed")
			}),
		},
	)

	mux := asynq.NewServeMux()
	mux.HandleFunc(pipeline.TaskTypeScan, handler.ProcessTask)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-quit; srv.Shutdown() }()

	log.Info().
		Str("redis", viper.GetString("redis.addr")).
		Int("concurrency", viper.GetInt("scanner.concurrency")).
		Msg("VSP Scanner worker starting")

	if err := srv.Run(mux); err != nil {
		log.Fatal().Err(err).Msg("worker failed")
	}
}
