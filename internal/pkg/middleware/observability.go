package middleware

import (
	"context"
	"log/slog"

	"connectrpc.com/connect"
	"github.com/qarven/oryon-go/internal/pkg/instrument"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// ChainIDHeader is the HTTP header used to propagate the chain ID across services.
const ChainIDHeader = "X-Chain-ID"

// ObservabilityInterceptor attaches a chain ID to the request context and logs requests and responses.
type ObservabilityInterceptor struct{}

// NewObservabilityInterceptor constructs an ObservabilityInterceptor.
func NewObservabilityInterceptor() *ObservabilityInterceptor {
	return &ObservabilityInterceptor{}
}

// WrapUnary attaches a chain ID to the context and logs the request and response.
func (i *ObservabilityInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		slog.InfoContext(ctx, "request received",
			"procedure", req.Spec().Procedure,
			"peer", req.Peer().Addr,
			"protocol", req.Peer().Protocol,
			"body", messageJSON(req.Any()),
		)

		resp, err := next(ctx, req)
		if err != nil {
			code := connect.CodeOf(err)

			slog.ErrorContext(ctx, "request failed",
				"procedure", req.Spec().Procedure,
				"code", code.String(),
				"error", err,
			)

			return resp, err
		}

		slog.InfoContext(ctx, "request completed",
			"procedure", req.Spec().Procedure,
			"body", messageJSON(resp.Any()),
		)

		resp.Header().Set(ChainIDHeader, instrument.GetCorrelationID(ctx))

		return resp, nil
	}
}

// WrapStreamingClient passes the call through unchanged.
func (i *ObservabilityInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return func(ctx context.Context, spec connect.Spec) connect.StreamingClientConn {
		return next(ctx, spec)
	}
}

// WrapStreamingHandler passes the call through unchanged.
func (i *ObservabilityInterceptor) WrapStreamingHandler(
	next connect.StreamingHandlerFunc,
) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		return next(ctx, conn)
	}
}

func messageJSON(msg any) string {
	protoMsg, ok := msg.(proto.Message)
	if !ok {
		return ""
	}

	data, err := protojson.Marshal(protoMsg)
	if err != nil {
		return ""
	}

	return string(data)
}
