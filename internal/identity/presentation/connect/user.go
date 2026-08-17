package connect

import (
	"context"

	"connectrpc.com/connect"
	v1 "github.com/qarven/mono/gen/go/oryon/identity/v1"
	"github.com/qarven/mono/gen/go/oryon/identity/v1/identityconnect"
	"github.com/qarven/oryon-go/internal/identity/application"
)

type UserService interface {
	Identities(ctx context.Context, input application.IdentitiesInput) (*application.IdentitiesOutput, error)
}

type UserServer struct {
	identityconnect.UnimplementedUserServiceHandler

	service UserService
}

func NewUserServer(service UserService) *UserServer {
	return &UserServer{
		service: service,
	}
}

func (s *UserServer) Users(ctx context.Context, req *connect.Request[v1.UsersRequest]) (
	*connect.Response[v1.UsersResponse], error) {
	resp, err := s.service.Identities(ctx, application.IdentitiesInput{
		Email: req.Msg.GetEmail(),
		Name:  req.Msg.GetName(),
	})
	if err != nil {
		return nil, err
	}

	users := make([]*v1.User, 0, len(resp.Identities))
	for _, identity := range resp.Identities {
		users = append(users, &v1.User{
			Id:   identity.ID,
			Name: identity.Name,
		})
	}

	return connect.NewResponse(&v1.UsersResponse{
		Users: users,
		Total: resp.Total,
	}), nil
}
