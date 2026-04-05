package telemetry

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

var Tracer trace.Tracer

// Init khởi tạo OpenTelemetry tracer.
// Nếu OTLP endpoint không có hoặc lỗi — fallback sang noop tracer (không crash).
// Gọi defer shutdown() trong main.
func Init(ctx context.Context, serviceName, version, otlpEndpoint string) (shutdown func(), err error) {
	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName(serviceName),
			semconv.ServiceVersion(version),
		),
	)
	if err != nil {
		return noop(), fmt.Errorf("telemetry: create resource: %w", err)
	}

	// Nếu không có endpoint — dùng noop, không lỗi
	if otlpEndpoint == "" {
		log.Info().Msg("telemetry: no OTLP endpoint configured — tracing disabled")
		Tracer = otel.Tracer(serviceName)
		return noop(), nil
	}

	exp, err := otlptracegrpc.New(ctx,
		otlptracegrpc.WithEndpoint(otlpEndpoint),
		otlptracegrpc.WithInsecure(),
	)
	if err != nil {
		log.Warn().Err(err).Msg("telemetry: failed to create OTLP exporter — tracing disabled")
		Tracer = otel.Tracer(serviceName)
		return noop(), nil
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp,
			sdktrace.WithMaxExportBatchSize(512),
			sdktrace.WithBatchTimeout(2*time.Second),
		),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.ParentBased(
			sdktrace.TraceIDRatioBased(0.1), // sample 10% by default
		)),
	)
	otel.SetTracerProvider(tp)
	Tracer = tp.Tracer(serviceName)
	log.Info().Str("endpoint", otlpEndpoint).Msg("telemetry: OTLP tracing enabled")

	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := tp.Shutdown(ctx); err != nil {
			log.Warn().Err(err).Msg("telemetry: shutdown error")
		}
	}, nil
}

func noop() func() { return func() {} }
