package middleware

import (
	"context"

	"connectrpc.com/connect/v2"
	"github.com/qarven/oryon-go/internal/pkg/meta"
)

func NewMetaInterceptor() connect.ServerInterceptor {
	return func(next connect.ServerFunc) connect.ServerFunc {
		return func(ctx context.Context, spec connect.Spec, stream connect.ServerStream) error {
			var peer, userAgent string

			if info, ok := connect.CallInfoForServerContext(ctx); ok && info != nil {
				peer = info.PeerAddr
				userAgent = info.RequestHeader().Get("User-Agent")
			}

			ctx = meta.SetMeta(ctx, meta.New(peer, userAgent))

			return next(ctx, spec, stream)
		}
	}
}
