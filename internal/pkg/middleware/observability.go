package middleware

import (
	"context"
	"log/slog"

	"connectrpc.com/connect/v2"
	"github.com/qarven/oryon-go/internal/pkg/instrument"
	"github.com/qarven/oryon-go/internal/pkg/uid"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// ChainIDHeader is the HTTP header used to propagate the chain ID across services.
const ChainIDHeader = "X-Chain-Id"

// NewObservabilityInterceptor attaches a chain ID to the request context and logs requests.
func NewObservabilityInterceptor() connect.ServerInterceptor {
	return func(next connect.ServerFunc) connect.ServerFunc {
		return func(ctx context.Context, spec connect.Spec, stream connect.ServerStream) error {
			ctx, meta := setupChainID(ctx)

			slog.InfoContext(ctx, "request received",
				"procedure", spec.Procedure,
				"peer", meta.peer,
				"protocol", meta.protocol,
			)

			if spec.StreamType != connect.StreamTypeUnary {
				return serveStream(ctx, next, spec, stream)
			}

			return serveUnary(ctx, next, spec, stream)
		}
	}
}

// requestMeta carries transport metadata resolved before the handler runs.
type requestMeta struct {
	peer     string
	protocol string
}

// setupChainID resolves or generates the chain ID, stores it in the context,
// and echoes it on the response header so it is flushed with the first send.
func setupChainID(ctx context.Context) (context.Context, requestMeta) {
	var meta requestMeta

	var chainID string

	info, hasInfo := connect.CallInfoForServerContext(ctx)
	if hasInfo && info != nil {
		chainID = info.RequestHeader().Get(ChainIDHeader)
		meta.peer = info.PeerAddr
		meta.protocol = info.Protocol
	}

	if chainID == "" {
		chainID = uid.NewUUID().Generate()
	}

	ctx = instrument.SetCorrelationID(ctx, chainID)

	if hasInfo && info != nil {
		info.ResponseHeader().Set(ChainIDHeader, chainID)
	}

	return ctx, meta
}

// serveStream runs non-unary RPCs without body logging.
func serveStream(
	ctx context.Context,
	next connect.ServerFunc,
	spec connect.Spec,
	stream connect.ServerStream,
) error {
	//nolint:godox // per-message body logging for streaming RPCs is planned follow-up work
	// TODO: add per-message body logging for streaming RPCs (client/server/bidi).
	err := next(ctx, spec, stream)
	if err != nil {
		slog.ErrorContext(ctx, "request failed",
			"procedure", spec.Procedure,
			"code", connect.CodeOf(err).String(),
			"error", err,
		)

		return err
	}

	slog.InfoContext(ctx, "request completed",
		"procedure", spec.Procedure,
	)

	return nil
}

// serveUnary runs unary RPCs while capturing request and response bodies for logging.
func serveUnary(
	ctx context.Context,
	next connect.ServerFunc,
	spec connect.Spec,
	stream connect.ServerStream,
) error {
	tracker := &unaryBodyTracker{}
	wrapped := &bodyLoggingStream{ServerStream: stream, tracker: tracker}

	err := next(ctx, spec, wrapped)
	if err != nil {
		slog.ErrorContext(ctx, "request failed",
			"procedure", spec.Procedure,
			"code", connect.CodeOf(err).String(),
			"error", err,
			"body", tracker.request,
		)

		return err
	}

	slog.InfoContext(ctx, "request completed",
		"procedure", spec.Procedure,
		"request_body", tracker.request,
		"response_body", tracker.response,
	)

	return nil
}

// unaryBodyTracker captures the first request and response bodies of a unary RPC.
type unaryBodyTracker struct {
	request        string
	response       string
	requestLogged  bool
	responseLogged bool
}

// bodyLoggingStream wraps a ServerStream to capture unary message bodies for logging.
type bodyLoggingStream struct {
	connect.ServerStream

	tracker *unaryBodyTracker
}

// Receive captures the request message body on success.
func (s *bodyLoggingStream) Receive(msg any) error {
	err := s.ServerStream.Receive(msg)
	if err == nil && !s.tracker.requestLogged {
		s.tracker.request = messageJSON(msg)
		s.tracker.requestLogged = true
	}

	return err
}

// Send captures the response message body before sending.
func (s *bodyLoggingStream) Send(msg any) error {
	if !s.tracker.responseLogged {
		s.tracker.response = messageJSON(msg)
		s.tracker.responseLogged = true
	}

	return s.ServerStream.Send(msg)
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
