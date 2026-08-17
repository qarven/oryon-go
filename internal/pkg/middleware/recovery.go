package middleware

import (
	"context"
	"log/slog"
	"runtime/debug"

	"connectrpc.com/connect"
	"github.com/qarven/oryon-go/internal/pkg/stacktrace"
)

// RecoveryInterceptor recovers panics and converts them into connect errors.
type RecoveryInterceptor struct{}

// NewRecoveryInterceptor constructs a RecoveryInterceptor.
func NewRecoveryInterceptor() *RecoveryInterceptor {
	return &RecoveryInterceptor{}
}

// WrapUnary recovers panics from the handler and returns them as connect errors.
func (i *RecoveryInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (_ connect.AnyResponse, retErr error) {
		defer func() {
			if rvr := recover(); rvr != nil {
				retErr = panicError(ctx, rvr)
			}
		}()

		return next(ctx, req)
	}
}

// WrapStreamingClient passes the call through unchanged.
func (i *RecoveryInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return func(ctx context.Context, spec connect.Spec) connect.StreamingClientConn {
		return next(ctx, spec)
	}
}

// WrapStreamingHandler recovers panics from the handler and returns them as connect errors.
func (i *RecoveryInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) (retErr error) {
		defer func() {
			if rvr := recover(); rvr != nil {
				retErr = panicError(ctx, rvr)
			}
		}()

		return next(ctx, conn)
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

	return connect.NewError(connect.CodeInternal, errInternal)
}
