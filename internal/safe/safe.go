package safe

import (
	"context"
	"github.com/rs/zerolog/log"
)

func Go(fn func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Error().Interface("panic", r).Msg("goroutine panic recovered")
			}
		}()
		fn()
	}()
}

func GoCtx(ctx context.Context, fn func(ctx context.Context)) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Error().Interface("panic", r).Msg("goroutine panic recovered")
			}
		}()
		fn(ctx)
	}()
}
