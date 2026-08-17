package middleware

import (
	"context"
	"strings"

	"connectrpc.com/connect"
	"github.com/qarven/oryon-go/internal/pkg/goerror"
	"github.com/qarven/oryon-go/internal/pkg/jwt"
)

// bearerScheme is the authentication scheme prefix in the Authorization header.
const bearerScheme = "Bearer "

// AuthenticationInterceptor verifies the access token on protected procedures.
type AuthenticationInterceptor struct {
	accessJWT        jwt.JWT
	publicProcedures map[string]struct{}
}

// NewAuthenticationInterceptor constructs an AuthenticationInterceptor.
func NewAuthenticationInterceptor(accessJWT jwt.JWT, publicEndpoints []string) *AuthenticationInterceptor {
	public := make(map[string]struct{}, len(publicEndpoints))
	for _, endpoint := range publicEndpoints {
		if endpoint = strings.TrimSpace(endpoint); endpoint != "" {
			public[endpoint] = struct{}{}
		}
	}

	return &AuthenticationInterceptor{
		accessJWT:        accessJWT,
		publicProcedures: public,
	}
}

// WrapUnary verifies the access token before invoking the handler.
func (i *AuthenticationInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		if i.isPublic(req.Spec().Procedure) {
			return next(ctx, req)
		}

		claims, err := i.authenticate(req.Header().Get("Authorization"))
		if err != nil {
			return nil, err
		}

		return next(jwt.SetAuth(ctx, *claims), req)
	}
}

// WrapStreamingClient passes the call through unchanged.
func (i *AuthenticationInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return func(ctx context.Context, spec connect.Spec) connect.StreamingClientConn {
		return next(ctx, spec)
	}
}

// WrapStreamingHandler verifies the access token before invoking the handler.
func (i *AuthenticationInterceptor) WrapStreamingHandler(
	next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		if i.isPublic(conn.Spec().Procedure) {
			return next(ctx, conn)
		}

		claims, err := i.authenticate(conn.RequestHeader().Get("Authorization"))
		if err != nil {
			return err
		}

		return next(jwt.SetAuth(ctx, *claims), conn)
	}
}

func (i *AuthenticationInterceptor) isPublic(procedure string) bool {
	_, ok := i.publicProcedures[procedure]

	return ok
}

func (i *AuthenticationInterceptor) authenticate(authorization string) (*jwt.Claims, error) {
	if !strings.HasPrefix(authorization, bearerScheme) {
		return nil, goerror.NewBusiness("missing bearer token", goerror.CodeUnauthorized)
	}

	claims, err := i.accessJWT.Verify(strings.TrimPrefix(authorization, bearerScheme))
	if err != nil {
		return nil, goerror.NewBusiness("invalid or expired access token", goerror.CodeUnauthorized)
	}

	return &claims, nil
}
