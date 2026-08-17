package connect

import (
	"context"

	"connectrpc.com/connect"
	v1 "github.com/qarven/mono/gen/go/oryon/identity/v1"
	"github.com/qarven/mono/gen/go/oryon/identity/v1/identityconnect"
	"github.com/qarven/oryon-go/internal/identity/application"
)

type AuthenticationService interface {
	Login(ctx context.Context, input application.LoginInput) (*application.LoginOutput, error)
	Logout(ctx context.Context, input application.LogoutInput) error
	RefreshToken(ctx context.Context, input application.RefreshTokenInput) (*application.RefreshTokenOutput, error)
	Users(ctx context.Context, input application.UsersInput) (*application.UsersOutput, error)
}

type AuthenticationServer struct {
	identityconnect.UnimplementedAuthenticationServiceHandler

	service AuthenticationService
}

func NewAuthenticationServer(service AuthenticationService) *AuthenticationServer {
	return &AuthenticationServer{ //nolint:exhaustruct // embedded Unimplemented*Handler follows the connect-go pattern
		service: service,
	}
}

func (s *AuthenticationServer) Login(ctx context.Context, req *connect.Request[v1.LoginRequest]) (
	*connect.Response[v1.LoginResponse], error) {
	resp, err := s.service.Login(ctx, application.LoginInput{
		Email:    req.Msg.GetEmail(),
		Password: req.Msg.GetPassword(),
	})
	if err != nil {
		return nil, err
	}

	return connect.NewResponse(&v1.LoginResponse{
		Token: &v1.Token{
			AccessToken:  resp.AccessToken,
			RefreshToken: resp.RefreshToken,
		},
	}), nil
}

func (s *AuthenticationServer) Logout(ctx context.Context, req *connect.Request[v1.LogoutRequest]) (
	*connect.Response[v1.LogoutResponse], error) {
	err := s.service.Logout(ctx, application.LogoutInput{
		RefreshToken: req.Msg.GetRefreshToken(),
	})
	if err != nil {
		return nil, err
	}

	return connect.NewResponse(&v1.LogoutResponse{}), nil
}

func (s *AuthenticationServer) RefreshToken(ctx context.Context, req *connect.Request[v1.RefreshTokenRequest]) (
	*connect.Response[v1.RefreshTokenResponse], error) {
	resp, err := s.service.RefreshToken(ctx, application.RefreshTokenInput{
		RefreshToken: req.Msg.GetRefreshToken(),
	})
	if err != nil {
		return nil, err
	}

	return connect.NewResponse(&v1.RefreshTokenResponse{
		Token: &v1.Token{
			AccessToken:  resp.AccessToken,
			RefreshToken: resp.RefreshToken,
		},
	}), nil
}
