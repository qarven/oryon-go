package middleware

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"github.com/qarven/oryon-go/internal/pkg/goerror"
)

var errInternal = errors.New("internal server error")

// ErrorInterceptor converts a goerror into a connect error.
type ErrorInterceptor struct{}

// NewErrorInterceptor constructs an ErrorInterceptor.
func NewErrorInterceptor() *ErrorInterceptor {
	return &ErrorInterceptor{}
}

// WrapUnary converts errors returned by the handler into connect errors.
func (i *ErrorInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		resp, err := next(ctx, req)
		if err != nil {
			return nil, toConnectError(err)
		}

		return resp, nil
	}
}

// WrapStreamingClient passes the call through unchanged.
func (i *ErrorInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return func(ctx context.Context, spec connect.Spec) connect.StreamingClientConn {
		return next(ctx, spec)
	}
}

// WrapStreamingHandler converts errors returned by the handler into connect errors.
func (i *ErrorInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		err := next(ctx, conn)
		if err != nil {
			return toConnectError(err)
		}

		return nil
	}
}

func toConnectError(err error) *connect.Error {
	if goErr, ok := errors.AsType[*goerror.Error](err); ok {
		return connect.NewError(toConnectCode(goErr.Code(), goErr))
	}

	if connectErr, ok := errors.AsType[*connect.Error](err); ok {
		return connectErr
	}

	return connect.NewError(connect.CodeInternal, errInternal)
}

func toConnectCode(code goerror.Code, err error) (connect.Code, error) {
	switch code {
	case goerror.CodeInvalidFormat, goerror.CodeInvalidInput:
		return connect.CodeInvalidArgument, err
	case goerror.CodeNotFound:
		return connect.CodeNotFound, err
	case goerror.CodeConflict:
		return connect.CodeAlreadyExists, err
	case goerror.CodeUnauthorized:
		return connect.CodeUnauthenticated, err
	case goerror.CodeForbidden:
		return connect.CodePermissionDenied, err
	case goerror.CodeTimeout:
		return connect.CodeDeadlineExceeded, err
	case goerror.CodeTooManyRequest:
		return connect.CodeResourceExhausted, err
	default:
		return connect.CodeInternal, errInternal
	}
}
