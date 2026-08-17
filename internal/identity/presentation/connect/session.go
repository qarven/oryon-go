package connect

import (
	"context"

	"connectrpc.com/connect"
	v1 "github.com/qarven/mono/gen/go/oryon/identity/v1"
	"github.com/qarven/mono/gen/go/oryon/identity/v1/identityconnect"
	"github.com/qarven/oryon-go/internal/identity/application"
)

type SessionService interface {
	GetCurrentSession(ctx context.Context, input application.GetCurrentSessionInput) (*application.GetCurrentSessionOutput, error)
	ListSessions(ctx context.Context, input application.ListSessionsInput) (*application.ListSessionsOutput, error)
	RevokeSession(ctx context.Context, input application.RevokeSessionInput) (*application.RevokeSessionOutput, error)
	RevokeAllOtherSessions(ctx context.Context, input application.RevokeAllOtherSessionsInput) (*application.RevokeAllOtherSessionsOutput, error)
	Logout(ctx context.Context, input application.LogoutInput) (*application.LogoutOutput, error)
}

type SessionServer struct {
	identityconnect.UnimplementedSessionServiceHandler
	service SessionService
}

func NewSessionServer(service SessionService) *SessionServer {
	return &SessionServer{service: service}
}

func (s *SessionServer) GetCurrentSession(ctx context.Context, req *connect.Request[v1.GetCurrentSessionRequest]) (*connect.Response[v1.GetCurrentSessionResponse], error) {
	out, err := s.service.GetCurrentSession(ctx, application.GetCurrentSessionInput{})
	if err != nil {
		return nil, err
	}
	resp := &v1.GetCurrentSessionResponse{
		Session: toProtoSession(out.Session, true),
	}
	return connect.NewResponse(resp), nil
}

func (s *SessionServer) ListSessions(ctx context.Context, req *connect.Request[v1.ListSessionsRequest]) (*connect.Response[v1.ListSessionsResponse], error) {
	input := application.ListSessionsInput{
		PageSize:       req.Msg.GetPageSize(),
		PageToken:      req.Msg.GetPageToken(),
		IncludeRevoked: req.Msg.GetIncludeRevoked(),
		IncludeExpired: req.Msg.GetIncludeExpired(),
	}
	out, err := s.service.ListSessions(ctx, input)
	if err != nil {
		return nil, err
	}
	var protos []*v1.Session
	for _, sess := range out.Sessions {
		protos = append(protos, toProtoSession(sess, false))
	}
	// Mark current as is_current if matches first (GetCurrentSession)
	// For simplicity, if we can detect current via GetCurrentSession, set true for matching id
	// We'll try to get current session to mark
	if curr, err := s.service.GetCurrentSession(ctx, application.GetCurrentSessionInput{}); err == nil {
		for _, p := range protos {
			if p.GetId() == curr.Session.ID {
				p.IsCurrent = true
			}
		}
	}
	resp := &v1.ListSessionsResponse{
		Sessions:      protos,
		NextPageToken: out.NextPageToken,
		TotalSize:     out.TotalSize,
	}
	return connect.NewResponse(resp), nil
}

func (s *SessionServer) RevokeSession(ctx context.Context, req *connect.Request[v1.RevokeSessionRequest]) (*connect.Response[v1.RevokeSessionResponse], error) {
	input := application.RevokeSessionInput{
		SessionID: req.Msg.GetSessionId(),
	}
	_, err := s.service.RevokeSession(ctx, input)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&v1.RevokeSessionResponse{}), nil
}

func (s *SessionServer) RevokeAllOtherSessions(ctx context.Context, req *connect.Request[v1.RevokeAllOtherSessionsRequest]) (*connect.Response[v1.RevokeAllOtherSessionsResponse], error) {
	out, err := s.service.RevokeAllOtherSessions(ctx, application.RevokeAllOtherSessionsInput{})
	if err != nil {
		return nil, err
	}
	resp := &v1.RevokeAllOtherSessionsResponse{
		RevokedCount: out.RevokedCount,
	}
	return connect.NewResponse(resp), nil
}

func (s *SessionServer) Logout(ctx context.Context, req *connect.Request[v1.LogoutRequest]) (*connect.Response[v1.LogoutResponse], error) {
	input := application.LogoutInput{
		RevokeRefreshTokens: req.Msg.GetRevokeRefreshTokens(),
	}
	if req.Msg.SessionId != nil {
		input.SessionID = req.Msg.SessionId
	}
	_, err := s.service.Logout(ctx, input)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&v1.LogoutResponse{}), nil
}
