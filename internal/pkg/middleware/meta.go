package middleware

import (
	"context"
	"net/http"

	"connectrpc.com/connect"
	"github.com/qarven/oryon-go/internal/pkg/meta"
)

// MetaInterceptor extracts peer IP and User-Agent from the request and
// stores them in the context as meta.Meta so handlers can use
// meta.GetMeta(ctx).Peer() / meta.GetMeta(ctx).UserAgent().
type MetaInterceptor struct{}

// NewMetaInterceptor constructs a MetaInterceptor.
func NewMetaInterceptor() *MetaInterceptor {
	return &MetaInterceptor{}
}

// WrapUnary extracts metadata from the unary request and injects it into the context.
func (i *MetaInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		m := meta.New(req.Peer().Addr, req.Header().Get("User-Agent"))
		ctx = meta.SetMeta(ctx, m)

		return next(ctx, req)
	}
}

// WrapStreamingClient passes the call through unchanged.
func (i *MetaInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return func(ctx context.Context, spec connect.Spec) connect.StreamingClientConn {
		return next(ctx, spec)
	}
}

// WrapStreamingHandler extracts metadata from the streaming handler connection.
func (i *MetaInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		m := meta.New(conn.Peer().Addr, conn.RequestHeader().Get("User-Agent"))
		ctx = meta.SetMeta(ctx, m)

		return next(ctx, conn)
	}
}

// WrapHTTP is an optional net/http middleware that populates meta for plain HTTP handlers.
func (i *MetaInterceptor) WrapHTTP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m := meta.New(r.RemoteAddr, r.Header.Get("User-Agent"))
		ctx := meta.SetMeta(r.Context(), m)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
