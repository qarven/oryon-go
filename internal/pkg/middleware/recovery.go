package middleware

import (
	"context"
	"log/slog"
	"runtime/debug"

	"connectrpc.com/connect/v2"
	"github.com/qarven/oryon-go/internal/pkg/stacktrace"
)

// NewRecoveryInterceptor recovers panics and converts them into connect errors.
func NewRecoveryInterceptor() connect.ServerInterceptor {
	return func(next connect.ServerFunc) connect.ServerFunc {
		return func(ctx context.Context, spec connect.Spec, stream connect.ServerStream) (retErr error) {
			defer func() {
				if rvr := recover(); rvr != nil {
					retErr = panicError(ctx, rvr)
				}
			}()

			return next(ctx, spec, stream)
		}
	}
}

func panicError(ctx context.Context, rvr any) *connect.Error {
	stack := debug.Stack()

	paths := stacktrace.InternalPaths(stack)
	if len(paths) == 0 {
		slog.ErrorContext(ctx, "panic occurred in connect handler", "panic", rvr, "stack", string(stack))
	} else {
		slog.ErrorContext(ctx, "panic occurred in connect handler", "panic", rvr, "stack", paths)
	}

	return connect.NewError(connect.CodeInternal, "internal server error")
}
