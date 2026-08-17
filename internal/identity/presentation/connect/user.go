package connect

import (
	"context"

	"connectrpc.com/connect"
	v1 "github.com/qarven/mono/gen/go/oryon/identity/v1"
	"github.com/qarven/mono/gen/go/oryon/identity/v1/identityconnect"
	"github.com/qarven/oryon-go/internal/identity/application"
)

type UserService interface {
	Users(ctx context.Context, input application.UsersInput) (*application.UsersOutput, error)
}

type UserServer struct {
	identityconnect.UnimplementedUserServiceHandler

	service UserService
}

func NewUserServer(service UserService) *UserServer {
	return &UserServer{ //nolint:exhaustruct // embedded Unimplemented*Handler follows the connect-go pattern
		service: service,
	}
}

func (s *UserServer) Users(ctx context.Context, req *connect.Request[v1.UsersRequest]) (
	*connect.Response[v1.UsersResponse], error) {
	resp, err := s.service.Users(ctx, application.UsersInput{
		Email: req.Msg.GetEmail(),
		Name:  req.Msg.GetName(),
	})
	if err != nil {
		return nil, err
	}

	users := make([]*v1.User, 0, len(resp.Users))
	for _, user := range resp.Users {
		users = append(users, &v1.User{
			Id:   user.ID,
			Name: user.Name,
		})
	}

	return connect.NewResponse(&v1.UsersResponse{
		Users: users,
		Total: resp.Total,
	}), nil
}
