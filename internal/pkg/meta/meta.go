package meta

import (
	"context"
	"strings"
)

type metaContextKey struct{}

// Meta holds request metadata extracted from transport headers.
type Meta struct {
	peer string // this is ip address of caller, Forwarded or X-Forwarded-For
	ua   string // this is user agent
}

// New creates a new Meta with given peer IP and user agent.
func New(peer, ua string) *Meta {
	return &Meta{
		peer: strings.TrimSpace(peer),
		ua:   strings.TrimSpace(ua),
	}
}

// Peer returns the caller IP address.
func (m *Meta) Peer() string {
	if m == nil {
		return ""
	}

	return m.peer
}

// UserAgent returns the caller User-Agent.
func (m *Meta) UserAgent() string {
	if m == nil {
		return ""
	}

	return m.ua
}

// IsZero reports whether Meta is nil or has no fields set.
func (m *Meta) IsZero() bool {
	return m == nil || (m.peer == "" && m.ua == "")
}

// String returns a debug representation.
func (m *Meta) String() string {
	if m == nil {
		return "Meta{<nil>}"
	}

	return "Meta{peer=" + m.peer + " ua=" + m.ua + "}"
}

// GetMeta returns the Meta stored in context, if any.
func GetMeta(ctx context.Context) *Meta {
	if ctx == nil {
		return nil
	}

	if m, ok := ctx.Value(metaContextKey{}).(*Meta); ok {
		return m
	}

	return nil
}

// SetMeta stores Meta into context.
func SetMeta(ctx context.Context, meta *Meta) context.Context {
	return context.WithValue(ctx, metaContextKey{}, meta)
}
