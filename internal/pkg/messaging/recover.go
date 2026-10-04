package messaging

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"

	"github.com/qarven/oryon-go/internal/pkg/stacktrace"
)

var ErrHandlerPanic = errors.New("pkgmessage: panic in handler")

func callHandlerWithRecover(ctx context.Context, kind string, operation func() error) (err error) {
	defer func() {
		if rvr := recover(); rvr != nil {
			stack := debug.Stack()

			paths := stacktrace.InternalPaths(stack)
			if len(paths) == 0 {
				slog.ErrorContext(ctx, "panic in messaging handler", "kind", kind, "panic", rvr, "stack", string(stack))
			} else {
				slog.ErrorContext(ctx, "panic in messaging handler", "kind", kind, "panic", rvr, "stack", paths)
			}

			err = fmt.Errorf("%w: %s: %v", ErrHandlerPanic, kind, rvr)
		}
	}()

	return operation()
}
