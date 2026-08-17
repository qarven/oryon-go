package middleware

import (
	"context"
	"errors"
	"strings"

	"connectrpc.com/connect"
)

var errMaintenance = errors.New("service is under maintenance")

// MaintenanceInterceptor blocks requests whose procedure matches a blocked endpoint.
type MaintenanceInterceptor struct {
	enabled   bool
	endpoints map[string]struct{}
}

// NewMaintenanceInterceptor constructs a MaintenanceInterceptor from exact procedure endpoints.
func NewMaintenanceInterceptor(endpoints []string) *MaintenanceInterceptor {
	blocked := make(map[string]struct{}, len(endpoints))
	for _, endpoint := range endpoints {
		if endpoint = strings.TrimSpace(endpoint); endpoint != "" {
			blocked[endpoint] = struct{}{}
		}
	}

	return &MaintenanceInterceptor{
		enabled:   len(blocked) > 0,
		endpoints: blocked,
	}
}

// WrapUnary blocks requests to procedures under maintenance.
func (i *MaintenanceInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		if i.enabled && i.isBlocked(req.Spec().Procedure) {
			return nil, connect.NewError(connect.CodeUnavailable, errMaintenance)
		}

		return next(ctx, req)
	}
}

// WrapStreamingClient passes the call through unchanged.
func (i *MaintenanceInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return func(ctx context.Context, spec connect.Spec) connect.StreamingClientConn {
		return next(ctx, spec)
	}
}

// WrapStreamingHandler blocks requests to procedures under maintenance.
func (i *MaintenanceInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		if i.enabled && i.isBlocked(conn.Spec().Procedure) {
			return connect.NewError(connect.CodeUnavailable, errMaintenance)
		}

		return next(ctx, conn)
	}
}

func (i *MaintenanceInterceptor) isBlocked(procedure string) bool {
	_, ok := i.endpoints[procedure]

	return ok
}