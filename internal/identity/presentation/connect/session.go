package connect

import (
	"context"

	v1 "github.com/qarven/mono/gen/go/oryon/identity/v1"
	"github.com/qarven/mono/gen/go/oryon/identity/v1/identityconnect"
	"github.com/qarven/oryon-go/internal/identity/application"
	"github.com/qarven/oryon-go/internal/pkg/config"
	"github.com/qarven/oryon-go/internal/pkg/meta"
)

type sessionService interface {
	Logout(ctx context.Context, input application.LogoutInput) (*application.LogoutOutput, error)
}

type SessionServer struct {
	identityconnect.UnimplementedSessionServiceHandler

	service sessionService
	config  config.Config
}

func NewSessionServer(service sessionService, config config.Config) *SessionServer {
	return &SessionServer{service: service, config: config}
}

func (s *SessionServer) Logout(ctx context.Context, req *v1.LogoutRequest) (*v1.LogoutResponse, error) {
	requestMeta := meta.GetMeta(ctx)

	_, err := s.service.Logout(ctx, application.LogoutInput{
		RefreshToken: req.GetRefreshToken(),
		Meta: application.MetaInput{
			IPAddress: requestMeta.Peer(),
			UserAgent: requestMeta.UserAgent(),
		},
	})
	if err != nil {
		return nil, err
	}

	return &v1.LogoutResponse{}, nil
}
