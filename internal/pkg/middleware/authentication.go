package middleware

import (
	"context"
	"strings"

	"connectrpc.com/connect/v2"
	"github.com/qarven/oryon-go/internal/pkg/goerror"
	"github.com/qarven/oryon-go/internal/pkg/jwt"
)

func NewAuthenticationInterceptor(accessJWT jwt.JWT, publicEndpoints []string) connect.ServerInterceptor {
	public := make(map[string]struct{}, len(publicEndpoints))
	for _, endpoint := range publicEndpoints {
		if endpoint = strings.TrimSpace(endpoint); endpoint != "" {
			public[endpoint] = struct{}{}
		}
	}

	return func(next connect.ServerFunc) connect.ServerFunc {
		return func(ctx context.Context, spec connect.Spec, stream connect.ServerStream) error {
			if _, ok := public[spec.Procedure]; ok {
				return next(ctx, spec, stream)
			}

			var authorization string

			if info, ok := connect.CallInfoForServerContext(ctx); ok && info != nil {
				authorization = info.RequestHeader().Get("Authorization")
			}

			claims, err := authenticate(accessJWT, authorization)
			if err != nil {
				return err
			}

			return next(jwt.SetAuth(ctx, *claims), spec, stream)
		}
	}
}

func authenticate(accessJWT jwt.JWT, authorization string) (*jwt.Claims, error) {
	if !strings.HasPrefix(authorization, "Bearer ") {
		return nil, goerror.NewBusiness("missing bearer token", goerror.CodeUnauthorized)
	}

	claims, err := accessJWT.Verify(strings.TrimPrefix(authorization, "Bearer "))
	if err != nil {
		return nil, goerror.NewBusiness("invalid or expired access token", goerror.CodeUnauthorized)
	}

	return &claims, nil
}
