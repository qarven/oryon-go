package connect

import (
	"context"

	"connectrpc.com/connect"
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

func (s *SessionServer) Logout(
	ctx context.Context,
	req *connect.Request[v1.LogoutRequest],
) (*connect.Response[v1.LogoutResponse], error) {
	requestMeta := meta.GetMeta(ctx)

	_, err := s.service.Logout(ctx, application.LogoutInput{
		RefreshToken: req.Msg.GetRefreshToken(),
		Meta: application.MetaInput{
			IPAddress: requestMeta.Peer(),
			UserAgent: requestMeta.UserAgent(),
		},
	})
	if err != nil {
		return nil, err
	}

	return connect.NewResponse(&v1.LogoutResponse{}), nil
}
