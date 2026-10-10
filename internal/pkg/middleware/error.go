package middleware

import (
	"context"
	"errors"

	"connectrpc.com/connect/v2"
	"github.com/qarven/oryon-go/internal/pkg/goerror"
)

// NewErrorInterceptor converts a goerror into a connect error.
func NewErrorInterceptor() connect.ServerInterceptor {
	return func(next connect.ServerFunc) connect.ServerFunc {
		return func(ctx context.Context, spec connect.Spec, stream connect.ServerStream) error {
			err := next(ctx, spec, stream)
			if err != nil {
				return toConnectError(err)
			}

			return nil
		}
	}
}

func toConnectError(err error) *connect.Error {
	if goErr, ok := errors.AsType[*goerror.Error](err); ok {
		return connect.NewError(toConnectCode(goErr.Code()), goErr.Msg()).WithCause(goErr)
	}

	if connectErr, ok := errors.AsType[*connect.Error](err); ok {
		return connectErr
	}

	return connect.NewError(connect.CodeInternal, "internal server error").WithCause(err)
}

func toConnectCode(code goerror.Code) connect.Code {
	switch code {
	case goerror.CodeInvalidFormat, goerror.CodeInvalidInput:
		return connect.CodeInvalidArgument
	case goerror.CodeNotFound:
		return connect.CodeNotFound
	case goerror.CodeConflict:
		return connect.CodeAlreadyExists
	case goerror.CodeUnauthorized:
		return connect.CodeUnauthenticated
	case goerror.CodeForbidden:
		return connect.CodePermissionDenied
	case goerror.CodeTimeout:
		return connect.CodeDeadlineExceeded
	case goerror.CodeTooManyRequest:
		return connect.CodeResourceExhausted
	default:
		return connect.CodeInternal
	}
}
