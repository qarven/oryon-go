package connect

import (
	"context"
	"net/http"

	"connectrpc.com/connect"
	v1 "github.com/qarven/mono/gen/go/oryon/identity/v1"
	"github.com/qarven/mono/gen/go/oryon/identity/v1/identityconnect"
	"github.com/qarven/oryon-go/internal/identity/application"
	"github.com/qarven/oryon-go/internal/identity/domain"
	"github.com/qarven/oryon-go/internal/pkg/config"
	"github.com/qarven/oryon-go/internal/pkg/meta"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type AuthenticationService interface {
	Registration(ctx context.Context, input application.RegistrationInput) (*application.RegistrationOutput, error)
	CompleteRegistration(ctx context.Context, input application.CompleteRegistrationInput) (*application.CompleteRegistrationOutput, error)

	Login(ctx context.Context, input application.LoginInput) (*application.LoginOutput, error)
	RefreshToken(ctx context.Context, input application.RefreshTokenInput) (*application.RefreshTokenOutput, error)
	CompleteMfa(ctx context.Context, input application.CompleteMfaInput) (*application.CompleteMfaOutput, error)

	// ChangePassword(ctx context.Context, input application.ChangePasswordInput) (*application.ChangePasswordOutput, error)
	// RequestPasswordReset(ctx context.Context, input application.RequestPasswordResetInput) (*application.RequestPasswordResetOutput, error)
	// ConfirmPasswordReset(ctx context.Context, input application.ConfirmPasswordResetInput) (*application.ConfirmPasswordResetOutput, error)

	InitiateVerification(ctx context.Context, input application.InitiateVerificationInput) (*application.InitiateVerificationOutput, error)
	// VerifyEmail(ctx context.Context, input application.VerifyEmailInput) (*application.VerifyEmailOutput, error)

	// BeginPasskeyRegistration(ctx context.Context, input application.BeginPasskeyRegistrationInput) (*application.BeginPasskeyRegistrationOutput, error)
	// FinishPasskeyRegistration(ctx context.Context, input application.FinishPasskeyRegistrationInput) (*application.FinishPasskeyRegistrationOutput, error)
	// BeginPasskeyLogin(ctx context.Context, input application.BeginPasskeyLoginInput) (*application.BeginPasskeyLoginOutput, error)
	// FinishPasskeyLogin(ctx context.Context, input application.FinishPasskeyLoginInput) (*application.FinishPasskeyLoginOutput, error)
}

type AuthenticationServer struct {
	identityconnect.UnimplementedAuthenticationServiceHandler

	service AuthenticationService
	config  config.Config
}

func NewAuthenticationServer(service AuthenticationService, config config.Config) *AuthenticationServer {
	return &AuthenticationServer{service: service, config: config}
}

func (s *AuthenticationServer) Registration(ctx context.Context, req *connect.Request[v1.RegistrationRequest]) (*connect.Response[v1.RegistrationResponse], error) {
	md := meta.GetMeta(ctx)

	out, err := s.service.Registration(ctx, application.RegistrationInput{
		Email:    req.Msg.Email,
		Password: req.Msg.GetPassword(),
		Name:     req.Msg.GetName(),
		Phone:    req.Msg.Phone,
		Meta: application.MetaInput{
			IPAddress: md.Peer(),
			UserAgent: md.UserAgent(),
		},
	})
	if err != nil {
		return nil, err
	}

	return connect.NewResponse(&v1.RegistrationResponse{Flow: &v1.AuthFlow{
		Id:        out.Flow.ID,
		FlowType:  v1.AuthFlowType(out.Flow.FlowType),
		FlowState: v1.AuthFlowState(out.Flow.FlowState),
		ExpiresAt: timestamppb.New(out.Flow.ExpiresAt),
	}}), nil
}

func (s *AuthenticationServer) CompleteRegistration(ctx context.Context, req *connect.Request[v1.CompleteRegistrationRequest]) (*connect.Response[v1.CompleteRegistrationResponse], error) {
	md := meta.GetMeta(ctx)

	out, err := s.service.CompleteRegistration(ctx, application.CompleteRegistrationInput{
		FlowID:    req.Msg.GetFlowId(),
		EmailCode: req.Msg.EmailCode,
		PhoneCode: req.Msg.PhoneCode,
		Meta: application.MetaInput{
			IPAddress: md.Peer(),
			UserAgent: md.UserAgent(),
		},
	})
	if err != nil {
		return nil, err
	}

	return connect.NewResponse(&v1.CompleteRegistrationResponse{User: &v1.User{
		Id:        out.User.ID,
		Status:    fromUserStatus(out.User.Status),
		Name:      out.User.Name,
		Username:  out.User.Username,
		AvatarUrl: out.User.AvatarURL,
		CreatedAt: timestamppb.New(out.User.CreatedAt),
		UpdatedAt: timestamppb.New(out.User.UpdatedAt),
	}}), nil
}

func (s *AuthenticationServer) Login(ctx context.Context, req *connect.Request[v1.LoginRequest]) (*connect.Response[v1.LoginResponse], error) {
	md := meta.GetMeta(ctx)

	out, err := s.service.Login(ctx, application.LoginInput{
		Identifier: req.Msg.GetIdentifier(),
		Password:   req.Msg.GetPassword(),
		Meta: application.MetaInput{
			IPAddress: md.Peer(),
			UserAgent: md.UserAgent(),
		},
	})
	if err != nil {
		return nil, err
	}

	resp := &v1.LoginResponse{
		MfaRequired: out.MFARequired,
	}

	if out.Token != nil && out.RefreshToken != nil {
		resp.Token = &v1.Token{
			AccessToken:  *out.Token,
			RefreshToken: *out.RefreshToken,
			TokenType:    domain.TokenType,
			ExpiresIn:    *out.TokenExpiresIn,
		}
	}

	var cookieString string

	if out.Session != nil {
		maxAge := int(s.config.GetDay("modules.identity.session.ttl").Seconds())
		cookie := &http.Cookie{
			Name:     "oryon-session",
			Value:    "rawSessionToken",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
			Domain:   ".oryon.com",
			Path:     "/",
			MaxAge:   maxAge,
		}
		cookieString = cookie.String()
	}

	if out.User != nil {
		resp.User = &v1.User{
			Id:        out.User.ID,
			Status:    fromUserStatus(out.User.Status),
			Name:      out.User.Name,
			Username:  out.User.Username,
			AvatarUrl: out.User.AvatarURL,
			CreatedAt: timestamppb.New(out.User.CreatedAt),
			UpdatedAt: timestamppb.New(out.User.UpdatedAt),
		}
	}

	if out.Flow != nil {
		resp.Flow = &v1.AuthFlow{
			Id:        out.Flow.ID,
			FlowType:  fromAuthFlowType(out.Flow.FlowType),
			FlowState: fromAuthFlowState(out.Flow.FlowState),
			ExpiresAt: timestamppb.New(out.Flow.ExpiresAt),
		}
	}

	if len(out.AvailableMFAMethods) > 0 {
		for _, m := range out.AvailableMFAMethods {
			resp.AvailableMfaMethods = append(resp.AvailableMfaMethods, fromMfaFactorType(m))
		}
	}

	res := connect.NewResponse(resp)
	if out.Session != nil {
		res.Header().Add("Set-Cookie", cookieString)
	}

	return res, nil
}

func (s *AuthenticationServer) RefreshToken(ctx context.Context, req *connect.Request[v1.RefreshTokenRequest]) (*connect.Response[v1.RefreshTokenResponse], error) {
	md := meta.GetMeta(ctx)

	out, err := s.service.RefreshToken(ctx, application.RefreshTokenInput{
		RefreshToken: req.Msg.GetRefreshToken(),
		Meta: application.MetaInput{
			IPAddress: md.Peer(),
			UserAgent: md.UserAgent(),
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

func (s *AuthenticationServer) CompleteMfa(ctx context.Context, req *connect.Request[v1.CompleteMfaRequest]) (*connect.Response[v1.CompleteMfaResponse], error) {
	md := meta.GetMeta(ctx)

	out, err := s.service.CompleteMfa(ctx, application.CompleteMfaInput{
		FlowID:     req.Msg.GetFlowId(),
		Code:       req.Msg.GetCode(),
		FactorType: toMfaFactorType(req.Msg.GetFactorType()),
		Meta: application.MetaInput{
			IPAddress: md.Peer(),
			UserAgent: md.UserAgent(),
		},
	})
	if err != nil {
		return nil, err
	}

	resp := &v1.CompleteMfaResponse{}

	if out.Token != nil && out.RefreshToken != nil {
		resp.Token = &v1.Token{
			AccessToken:  *out.Token,
			RefreshToken: *out.RefreshToken,
			TokenType:    domain.TokenType,
			ExpiresIn:    *out.TokenExpiresIn,
		}
	}

	if out.User != nil {
		resp.User = &v1.User{
			Id:        out.User.ID,
			Status:    fromUserStatus(out.User.Status),
			Name:      out.User.Name,
			Username:  out.User.Username,
			AvatarUrl: out.User.AvatarURL,
			CreatedAt: timestamppb.New(out.User.CreatedAt),
			UpdatedAt: timestamppb.New(out.User.UpdatedAt),
		}
	}

	return connect.NewResponse(resp), nil
}

func (s *AuthenticationServer) InitiateVerification(ctx context.Context, req *connect.Request[v1.InitiateVerificationRequest]) (*connect.Response[v1.InitiateVerificationResponse], error) {
	md := meta.GetMeta(ctx)

	out, err := s.service.InitiateVerification(ctx, application.InitiateVerificationInput{
		FlowID:     req.Msg.FlowId,
		Identifier: req.Msg.GetIdentifier(),
		Purpose:    toVerificationPurpose(req.Msg.GetPurpose()),
		Meta: application.MetaInput{
			IPAddress: md.Peer(),
			UserAgent: md.UserAgent(),
		},
	})
	if err != nil {
		return nil, err
	}

	resp := &v1.InitiateVerificationResponse{}

	if out.Challenge != nil {
		resp.Challenge = &v1.VerificationChallenge{
			Id:         out.Challenge.ID,
			Identifier: out.Challenge.Identifier,
			Purpose:    fromVerificationPurpose(out.Challenge.Purpose),
			ExpiresAt:  timestamppb.New(out.Challenge.ExpiresAt),
		}
	}

	return connect.NewResponse(resp), nil
}
