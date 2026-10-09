package connect

import (
	"context"

	"connectrpc.com/connect"
	v1 "github.com/qarven/mono/gen/go/oryon/identity/v1"
	"github.com/qarven/mono/gen/go/oryon/identity/v1/identityconnect"
	"github.com/qarven/oryon-go/internal/identity/application"
	"github.com/qarven/oryon-go/internal/identity/domain"
	"github.com/qarven/oryon-go/internal/pkg/config"
	"github.com/qarven/oryon-go/internal/pkg/meta"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type registerService interface {
	Registration(ctx context.Context, input application.RegistrationInput) (*application.RegistrationOutput, error)
	CompleteRegistration(ctx context.Context, input application.CompleteRegistrationInput) (
		*application.CompleteRegistrationOutput, error)
	ResendRegistrationCode(ctx context.Context, input application.ResendRegistrationCodeInput) (
		*application.ResendRegistrationCodeOutput, error)
}

type loginService interface {
	Login(ctx context.Context, input application.LoginInput) (*application.LoginOutput, error)
	RefreshToken(ctx context.Context, input application.RefreshTokenInput) (*application.RefreshTokenOutput, error)
	CompleteLoginMfa(ctx context.Context, input application.CompleteLoginMfaInput) (
		*application.CompleteLoginMfaOutput, error)
}

type passwordResetService interface {
	InitiatePasswordReset(ctx context.Context, input application.InitiatePasswordResetInput) (
		*application.InitiatePasswordResetOutput, error)
	CompletePasswordReset(ctx context.Context, input application.CompletePasswordResetInput) (
		*application.CompletePasswordResetOutput, error)
}

type AuthenticationService interface {
	registerService
	loginService
	passwordResetService
}

type AuthenticationServer struct {
	identityconnect.UnimplementedAuthenticationServiceHandler

	service AuthenticationService
	config  config.Config
}

func NewAuthenticationServer(service AuthenticationService, config config.Config) *AuthenticationServer {
	return &AuthenticationServer{service: service, config: config}
}

func (s *AuthenticationServer) Registration(
	ctx context.Context,
	req *connect.Request[v1.RegistrationRequest],
) (*connect.Response[v1.RegistrationResponse], error) {
	requestMeta := meta.GetMeta(ctx)

	out, err := s.service.Registration(ctx, application.RegistrationInput{
		Email:    req.Msg.Email,
		Password: req.Msg.GetPassword(),
		Name:     req.Msg.GetName(),
		Phone:    req.Msg.Phone,
		Meta: application.MetaInput{
			IPAddress: requestMeta.Peer(),
			UserAgent: requestMeta.UserAgent(),
		},
	})
	if err != nil {
		return nil, err
	}

	return connect.NewResponse(&v1.RegistrationResponse{Flow: &v1.AuthFlow{
		Id:        out.Flow.ID.String(),
		FlowType:  fromAuthFlowType(out.Flow.FlowType),
		FlowState: fromAuthFlowState(out.Flow.FlowState),
		ExpiresAt: timestamppb.New(out.Flow.ExpiresAt),
	}}), nil
}

func (s *AuthenticationServer) CompleteRegistration(
	ctx context.Context,
	req *connect.Request[v1.CompleteRegistrationRequest],
) (*connect.Response[v1.CompleteRegistrationResponse], error) {
	requestMeta := meta.GetMeta(ctx)

	out, err := s.service.CompleteRegistration(ctx, application.CompleteRegistrationInput{
		FlowID:    domain.IDFrom(req.Msg.GetFlowId()),
		EmailCode: req.Msg.EmailCode,
		PhoneCode: req.Msg.PhoneCode,
		Meta: application.MetaInput{
			IPAddress: requestMeta.Peer(),
			UserAgent: requestMeta.UserAgent(),
		},
	})
	if err != nil {
		return nil, err
	}

	return connect.NewResponse(&v1.CompleteRegistrationResponse{User: &v1.User{
		Id:        out.User.ID.String(),
		Status:    fromUserStatus(out.User.Status),
		Name:      out.User.Name,
		Username:  out.User.Username,
		AvatarUrl: out.User.AvatarURL,
		CreatedAt: timestamppb.New(out.User.CreatedAt),
		UpdatedAt: timestamppb.New(out.User.UpdatedAt),
	}}), nil
}

func (s *AuthenticationServer) ResendRegistrationCode(
	ctx context.Context,
	req *connect.Request[v1.ResendRegistrationCodeRequest],
) (*connect.Response[v1.ResendRegistrationCodeResponse], error) {
	requestMeta := meta.GetMeta(ctx)

	out, err := s.service.ResendRegistrationCode(ctx, application.ResendRegistrationCodeInput{
		FlowID: domain.IDFrom(req.Msg.GetFlowId()),
		Meta: application.MetaInput{
			IPAddress: requestMeta.Peer(),
			UserAgent: requestMeta.UserAgent(),
		},
	})
	if err != nil {
		return nil, err
	}

	return connect.NewResponse(&v1.ResendRegistrationCodeResponse{Flow: &v1.AuthFlow{
		Id:        out.Flow.ID.String(),
		FlowType:  fromAuthFlowType(out.Flow.FlowType),
		FlowState: fromAuthFlowState(out.Flow.FlowState),
		ExpiresAt: timestamppb.New(out.Flow.ExpiresAt),
	}}), nil
}

func (s *AuthenticationServer) Login(
	ctx context.Context,
	req *connect.Request[v1.LoginRequest],
) (*connect.Response[v1.LoginResponse], error) {
	requestMeta := meta.GetMeta(ctx)

	out, err := s.service.Login(ctx, application.LoginInput{
		Identifier: req.Msg.GetIdentifier(),
		Password:   req.Msg.GetPassword(),
		Meta: application.MetaInput{
			IPAddress: requestMeta.Peer(),
			UserAgent: requestMeta.UserAgent(),
		},
	})
	if err != nil {
		return nil, err
	}

	if out.MFA != nil {
		availableMfaMethods := make([]v1.MfaFactorType, 0, len(out.MFA.AvailableMFAMethods))
		for _, m := range out.MFA.AvailableMFAMethods {
			availableMfaMethods = append(availableMfaMethods, fromMfaFactorType(m))
		}

		return connect.NewResponse(&v1.LoginResponse{Result: &v1.LoginResponse_LoginMfa{LoginMfa: &v1.LoginMfa{
			Flow: &v1.AuthFlow{
				Id:        out.MFA.Flow.ID.String(),
				FlowType:  fromAuthFlowType(out.MFA.Flow.FlowType),
				FlowState: fromAuthFlowState(out.MFA.Flow.FlowState),
				ExpiresAt: timestamppb.New(out.MFA.Flow.ExpiresAt),
			},
			AvailableMfaMethods: availableMfaMethods,
		}}}), nil
	}

	if out.Token != nil {
		return connect.NewResponse(&v1.LoginResponse{Result: &v1.LoginResponse_LoginToken{LoginToken: &v1.LoginToken{
			Token: &v1.Token{
				AccessToken:  out.Token.AccessToken,
				RefreshToken: out.Token.RefreshToken,
				TokenType:    domain.TokenType,
				ExpiresIn:    out.Token.ExpiresIn,
			},
			User: &v1.User{
				Id:        out.Token.User.ID.String(),
				Status:    fromUserStatus(out.Token.User.Status),
				Name:      out.Token.User.Name,
				Username:  out.Token.User.Username,
				AvatarUrl: out.Token.User.AvatarURL,
				CreatedAt: timestamppb.New(out.Token.User.CreatedAt),
				UpdatedAt: timestamppb.New(out.Token.User.UpdatedAt),
			},
		}}}), nil
	}

	return connect.NewResponse(&v1.LoginResponse{}), nil
}

func (s *AuthenticationServer) RefreshToken(
	ctx context.Context,
	req *connect.Request[v1.RefreshTokenRequest],
) (*connect.Response[v1.RefreshTokenResponse], error) {
	requestMeta := meta.GetMeta(ctx)

	out, err := s.service.RefreshToken(ctx, application.RefreshTokenInput{
		RefreshToken: req.Msg.GetRefreshToken(),
		Meta: application.MetaInput{
			IPAddress: requestMeta.Peer(),
			UserAgent: requestMeta.UserAgent(),
		},
	})
	if err != nil {
		return nil, err
	}

	return connect.NewResponse(&v1.RefreshTokenResponse{Token: &v1.Token{
		AccessToken:  out.Token,
		RefreshToken: out.RefreshToken,
		TokenType:    domain.TokenType,
		ExpiresIn:    out.ExpiresIn,
	}}), nil
}

func (s *AuthenticationServer) CompleteLoginMfa(
	ctx context.Context,
	req *connect.Request[v1.CompleteLoginMfaRequest],
) (*connect.Response[v1.CompleteLoginMfaResponse], error) {
	requestMeta := meta.GetMeta(ctx)

	out, err := s.service.CompleteLoginMfa(ctx, application.CompleteLoginMfaInput{
		FlowID:     domain.IDFrom(req.Msg.GetFlowId()),
		Code:       req.Msg.GetCode(),
		FactorType: toMfaFactorType(req.Msg.GetFactorType()),
		Meta: application.MetaInput{
			IPAddress: requestMeta.Peer(),
			UserAgent: requestMeta.UserAgent(),
		},
	})
	if err != nil {
		return nil, err
	}

	return connect.NewResponse(&v1.CompleteLoginMfaResponse{
		Token: &v1.Token{
			AccessToken:  out.Token,
			RefreshToken: out.RefreshToken,
			TokenType:    domain.TokenType,
			ExpiresIn:    out.TokenExpiresIn,
		},
		User: &v1.User{
			Id:        out.User.ID.String(),
			Status:    fromUserStatus(out.User.Status),
			Name:      out.User.Name,
			Username:  out.User.Username,
			AvatarUrl: out.User.AvatarURL,
			CreatedAt: timestamppb.New(out.User.CreatedAt),
			UpdatedAt: timestamppb.New(out.User.UpdatedAt),
		},
	}), nil
}

func (s *AuthenticationServer) InitiatePasswordReset(
	ctx context.Context,
	req *connect.Request[v1.InitiatePasswordResetRequest],
) (*connect.Response[v1.InitiatePasswordResetResponse], error) {
	requestMeta := meta.GetMeta(ctx)

	_, err := s.service.InitiatePasswordReset(ctx, application.InitiatePasswordResetInput{
		Identifier: req.Msg.GetIdentifier(),
		Meta: application.MetaInput{
			IPAddress: requestMeta.Peer(),
			UserAgent: requestMeta.UserAgent(),
		},
	})
	if err != nil {
		return nil, err
	}

	return connect.NewResponse(&v1.InitiatePasswordResetResponse{}), nil
}

func (s *AuthenticationServer) CompletePasswordReset(
	ctx context.Context,
	req *connect.Request[v1.CompletePasswordResetRequest],
) (*connect.Response[v1.CompletePasswordResetResponse], error) {
	requestMeta := meta.GetMeta(ctx)

	out, err := s.service.CompletePasswordReset(ctx, application.CompletePasswordResetInput{
		Code:        req.Msg.GetCode(),
		NewPassword: req.Msg.GetNewPassword(),
		Meta: application.MetaInput{
			IPAddress: requestMeta.Peer(),
			UserAgent: requestMeta.UserAgent(),
		},
	})
	if err != nil {
		return nil, err
	}

	return connect.NewResponse(&v1.CompletePasswordResetResponse{User: &v1.User{
		Id:        out.User.ID.String(),
		Status:    fromUserStatus(out.User.Status),
		Name:      out.User.Name,
		Username:  out.User.Username,
		AvatarUrl: out.User.AvatarURL,
		CreatedAt: timestamppb.New(out.User.CreatedAt),
		UpdatedAt: timestamppb.New(out.User.UpdatedAt),
	}}), nil
}
