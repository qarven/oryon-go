package middleware

import (
	"context"
	"strings"

	"connectrpc.com/connect/v2"
)

func NewMaintenanceInterceptor(endpoints []string) connect.ServerInterceptor {
	blocked := make(map[string]struct{}, len(endpoints))
	for _, endpoint := range endpoints {
		if endpoint = strings.TrimSpace(endpoint); endpoint != "" {
			blocked[endpoint] = struct{}{}
		}
	}

	enabled := len(blocked) > 0

	return func(next connect.ServerFunc) connect.ServerFunc {
		return func(ctx context.Context, spec connect.Spec, stream connect.ServerStream) error {
			if enabled {
				if _, ok := blocked[spec.Procedure]; ok {
					return connect.NewError(connect.CodeUnavailable, "service is under maintenance")
				}
			}

			return next(ctx, spec, stream)
		}
	}
}
