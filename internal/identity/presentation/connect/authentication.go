package connect

import (
	"context"

	"connectrpc.com/connect"
	v1 "github.com/qarven/mono/gen/go/oryon/identity/v1"
	"github.com/qarven/mono/gen/go/oryon/identity/v1/identityconnect"
	"github.com/qarven/oryon-go/internal/identity/application"
	"github.com/qarven/oryon-go/internal/identity/domain"
	"github.com/qarven/oryon-go/internal/pkg/meta"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type AuthenticationService interface {
	Registration(ctx context.Context, input application.RegistrationInput) (*application.RegistrationOutput, error)
	Login(ctx context.Context, input application.LoginInput) (*application.LoginOutput, error)
	CompleteMfa(ctx context.Context, input application.CompleteMfaInput) (*application.CompleteMfaOutput, error)
	RefreshToken(ctx context.Context, input application.RefreshTokenInput) (*application.RefreshTokenOutput, error)
	ChangePassword(ctx context.Context, input application.ChangePasswordInput) (*application.ChangePasswordOutput, error)
	RequestPasswordReset(ctx context.Context, input application.RequestPasswordResetInput) (*application.RequestPasswordResetOutput, error)
	ConfirmPasswordReset(ctx context.Context, input application.ConfirmPasswordResetInput) (*application.ConfirmPasswordResetOutput, error)
	RequestEmailVerification(ctx context.Context, input application.RequestEmailVerificationInput) (*application.RequestEmailVerificationOutput, error)
	VerifyEmail(ctx context.Context, input application.VerifyEmailInput) (*application.VerifyEmailOutput, error)
	BeginPasskeyRegistration(ctx context.Context, input application.BeginPasskeyRegistrationInput) (*application.BeginPasskeyRegistrationOutput, error)
	FinishPasskeyRegistration(ctx context.Context, input application.FinishPasskeyRegistrationInput) (*application.FinishPasskeyRegistrationOutput, error)
	BeginPasskeyLogin(ctx context.Context, input application.BeginPasskeyLoginInput) (*application.BeginPasskeyLoginOutput, error)
	FinishPasskeyLogin(ctx context.Context, input application.FinishPasskeyLoginInput) (*application.FinishPasskeyLoginOutput, error)
}

type AuthenticationServer struct {
	identityconnect.UnimplementedAuthenticationServiceHandler
	service AuthenticationService
}

func NewAuthenticationServer(service AuthenticationService) *AuthenticationServer {
	return &AuthenticationServer{service: service}
}

func (s *AuthenticationServer) Registration(ctx context.Context, req *connect.Request[v1.RegistrationRequest]) (*connect.Response[v1.RegistrationResponse], error) {
	out, err := s.service.Registration(ctx, application.RegistrationInput{
		Email:    req.Msg.Email,
		Password: req.Msg.GetPassword(),
		Name:     req.Msg.GetName(),
		Phone:    req.Msg.Phone,
	})
	if err != nil {
		return nil, err
	}

	resp := &v1.RegistrationResponse{
		User:                 toProtoUser(out.User),
		VerificationRequired: out.VerificationRequired,
	}

	if out.Flow != nil {
		resp.Flow = toProtoAuthFlow(*out.Flow)
	}

	return connect.NewResponse(resp), nil
}

func (s *AuthenticationServer) Login(ctx context.Context, req *connect.Request[v1.LoginRequest]) (*connect.Response[v1.LoginResponse], error) {
	md := meta.GetMeta(ctx)

	out, err := s.service.Login(ctx, application.LoginInput{
		Identifier: req.Msg.GetIdentifier(),
		Password:   req.Msg.Password,
		FlowID:     req.Msg.FlowId,
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
		NextStep:    out.NextStep,
	}

	if out.Token != nil && out.RefreshToken != nil {
		expiresAt := timestamppb.Now()
		var expiresIn int64 = 900
		if out.Session != nil {
			expiresAt = timestamppb.New(out.Session.ExpiresAt)
			expiresIn = int64(out.Session.ExpiresAt.Sub(out.Session.CreatedAt).Seconds())
		}
		resp.Token = toProtoToken(*out.Token, *out.RefreshToken, expiresAt, expiresIn)
	}
	if out.Session != nil {
		resp.Session = toProtoSession(*out.Session, true)
	}
	if out.User != nil {
		resp.User = toProtoUser(*out.User)
	}
	if out.Flow != nil {
		resp.Flow = toProtoAuthFlow(*out.Flow)
	}
	if len(out.AvailableMFAMethods) > 0 {
		for _, m := range out.AvailableMFAMethods {
			var protoTyp v1.MfaFactorType
			switch m {
			case domain.MfaFactorTypeTOTP:
				protoTyp = v1.MfaFactorType_MFA_FACTOR_TYPE_TOTP
			case domain.MfaFactorTypeSMS:
				protoTyp = v1.MfaFactorType_MFA_FACTOR_TYPE_SMS
			case domain.MfaFactorTypeEmail:
				protoTyp = v1.MfaFactorType_MFA_FACTOR_TYPE_EMAIL
			case domain.MfaFactorTypeWebAuthn:
				protoTyp = v1.MfaFactorType_MFA_FACTOR_TYPE_WEBAUTHN
			case domain.MfaFactorTypeBackupCode:
				protoTyp = v1.MfaFactorType_MFA_FACTOR_TYPE_BACKUP_CODE
			default:
				protoTyp = v1.MfaFactorType_MFA_FACTOR_TYPE_UNSPECIFIED
			}
			resp.AvailableMfaMethods = append(resp.AvailableMfaMethods, protoTyp)
		}
	}
	return connect.NewResponse(resp), nil
}

/*
func (s *AuthenticationServer) CompleteMfa(ctx context.Context, req *connect.Request[v1.CompleteMfaRequest]) (*connect.Response[v1.CompleteMfaResponse], error) {
	md := meta.GetMeta(ctx)
	input := application.CompleteMfaInput{
		FlowID:     req.Msg.GetFlowId(),
		Code:       req.Msg.GetCode(),
		FactorType: domain.MfaFactorType(req.Msg.GetFactorType()),
		IPAddress:  ip,
		UserAgent:  ua,
	}
	if req.Msg.FactorId != nil {
		input.FactorID = req.Msg.FactorId
	}
	out, err := s.service.CompleteMfa(ctx, input)
	if err != nil {
		return nil, err
	}
	expiresAt := timestamppb.New(out.Session.ExpiresAt)
	expiresIn := int64(out.Session.ExpiresAt.Sub(out.Session.CreatedAt).Seconds())
	resp := &v1.CompleteMfaResponse{
		Token:   toProtoToken(out.Token, out.RefreshToken, expiresAt, expiresIn),
		Session: toProtoSession(out.Session, true),
		User:    toProtoUser(out.User),
	}
	return connect.NewResponse(resp), nil
}

func (s *AuthenticationServer) RefreshToken(ctx context.Context, req *connect.Request[v1.RefreshTokenRequest]) (*connect.Response[v1.RefreshTokenResponse], error) {
	md := meta.GetMeta(ctx)
	input := application.RefreshTokenInput{
		RefreshToken: req.Msg.GetRefreshToken(),
		IPAddress:    ip,
		UserAgent:    ua,
	}
	out, err := s.service.RefreshToken(ctx, input)
	if err != nil {
		return nil, err
	}
	expiresAt := timestamppb.New(out.Session.ExpiresAt)
	expiresIn := int64(out.Session.ExpiresAt.Sub(out.Session.CreatedAt).Seconds())
	resp := &v1.RefreshTokenResponse{
		Token:   toProtoToken(out.Token, out.RefreshToken, expiresAt, expiresIn),
		Session: toProtoSession(out.Session, true),
	}
	return connect.NewResponse(resp), nil
}

func (s *AuthenticationServer) ChangePassword(ctx context.Context, req *connect.Request[v1.ChangePasswordRequest]) (*connect.Response[v1.ChangePasswordResponse], error) {
	input := application.ChangePasswordInput{
		CurrentPassword: req.Msg.GetCurrentPassword(),
		NewPassword:     req.Msg.GetNewPassword(),
	}
	_, err := s.service.ChangePassword(ctx, input)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&v1.ChangePasswordResponse{}), nil
}

func (s *AuthenticationServer) RequestPasswordReset(ctx context.Context, req *connect.Request[v1.RequestPasswordResetRequest]) (*connect.Response[v1.RequestPasswordResetResponse], error) {
	md := meta.GetMeta(ctx)
	input := application.RequestPasswordResetInput{
		Email:     req.Msg.GetEmail(),
		IPAddress: ip,
		UserAgent: ua,
	}
	out, err := s.service.RequestPasswordReset(ctx, input)
	if err != nil {
		return nil, err
	}
	resp := &v1.RequestPasswordResetResponse{}
	if out.VerificationID != nil {
		resp.VerificationId = out.VerificationID
	}
	return connect.NewResponse(resp), nil
}

func (s *AuthenticationServer) ConfirmPasswordReset(ctx context.Context, req *connect.Request[v1.ConfirmPasswordResetRequest]) (*connect.Response[v1.ConfirmPasswordResetResponse], error) {
	input := application.ConfirmPasswordResetInput{
		Token:       req.Msg.GetToken(),
		NewPassword: req.Msg.GetNewPassword(),
	}
	if req.Msg.Code != nil {
		input.Code = req.Msg.Code
	}
	out, err := s.service.ConfirmPasswordReset(ctx, input)
	if err != nil {
		return nil, err
	}
	resp := &v1.ConfirmPasswordResetResponse{}
	if out.Token != nil {
		// If token present, set; but our output currently has Token *string not used - we return empty
		_ = out.RefreshToken
	}
	return connect.NewResponse(resp), nil
}

func (s *AuthenticationServer) RequestEmailVerification(ctx context.Context, req *connect.Request[v1.RequestEmailVerificationRequest]) (*connect.Response[v1.RequestEmailVerificationResponse], error) {
	input := application.RequestEmailVerificationInput{}
	if req.Msg.Email != nil {
		input.Email = req.Msg.Email
	}
	if req.Msg.EmailId != nil {
		input.EmailID = req.Msg.EmailId
	}
	out, err := s.service.RequestEmailVerification(ctx, input)
	if err != nil {
		return nil, err
	}
	resp := &v1.RequestEmailVerificationResponse{
		Challenge: toProtoVerificationChallenge(out.Challenge),
	}
	return connect.NewResponse(resp), nil
}

func (s *AuthenticationServer) VerifyEmail(ctx context.Context, req *connect.Request[v1.VerifyEmailRequest]) (*connect.Response[v1.VerifyEmailResponse], error) {
	input := application.VerifyEmailInput{
		Token: req.Msg.GetToken(),
	}
	if req.Msg.Code != nil {
		input.Code = req.Msg.Code
	}
	if req.Msg.VerificationId != nil {
		input.VerificationID = req.Msg.VerificationId
	}
	if req.Msg.Email != nil {
		input.Email = req.Msg.Email
	}
	out, err := s.service.VerifyEmail(ctx, input)
	if err != nil {
		return nil, err
	}
	resp := &v1.VerifyEmailResponse{
		Email:    toProtoUserEmail(out.Email),
		Verified: out.Verified,
	}
	return connect.NewResponse(resp), nil
}

func (s *AuthenticationServer) RequestMagicLink(ctx context.Context, req *connect.Request[v1.RequestMagicLinkRequest]) (*connect.Response[v1.RequestMagicLinkResponse], error) {
	md := meta.GetMeta(ctx)
	input := application.RequestMagicLinkInput{
		Email:     req.Msg.GetEmail(),
		IPAddress: ip,
		UserAgent: ua,
	}
	if req.Msg.RedirectUrl != nil {
		input.RedirectURL = req.Msg.RedirectUrl
	}
	out, err := s.service.RequestMagicLink(ctx, input)
	if err != nil {
		return nil, err
	}
	resp := &v1.RequestMagicLinkResponse{}
	if out.Challenge != nil {
		ch := toProtoVerificationChallenge(*out.Challenge)
		resp.Challenge = ch
	}
	return connect.NewResponse(resp), nil
}

func (s *AuthenticationServer) ConsumeMagicLink(ctx context.Context, req *connect.Request[v1.ConsumeMagicLinkRequest]) (*connect.Response[v1.ConsumeMagicLinkResponse], error) {
	md := meta.GetMeta(ctx)
	input := application.ConsumeMagicLinkInput{
		Token:     req.Msg.GetToken(),
		IPAddress: ip,
		UserAgent: ua,
	}
	out, err := s.service.ConsumeMagicLink(ctx, input)
	if err != nil {
		return nil, err
	}
	expiresAt := timestamppb.New(out.Session.ExpiresAt)
	expiresIn := int64(out.Session.ExpiresAt.Sub(out.Session.CreatedAt).Seconds())
	resp := &v1.ConsumeMagicLinkResponse{
		Token:   toProtoToken(out.Token, out.RefreshToken, expiresAt, expiresIn),
		Session: toProtoSession(out.Session, true),
		User:    toProtoUser(out.User),
	}
	return connect.NewResponse(resp), nil
}

func (s *AuthenticationServer) BeginPasskeyRegistration(ctx context.Context, req *connect.Request[v1.BeginPasskeyRegistrationRequest]) (*connect.Response[v1.BeginPasskeyRegistrationResponse], error) {
	md := meta.GetMeta(ctx)
	input := application.BeginPasskeyRegistrationInput{
		Name:      req.Msg.GetName(),
		IPAddress: ip,
		UserAgent: ua,
	}
	if req.Msg.FlowId != nil {
		input.FlowID = req.Msg.FlowId
	}
	out, err := s.service.BeginPasskeyRegistration(ctx, input)
	if err != nil {
		return nil, err
	}
	resp := &v1.BeginPasskeyRegistrationResponse{
		CreationOptionsJson: out.CreationOptionsJSON,
		FlowId:              out.FlowID,
		Flow:                toProtoAuthFlow(out.Flow),
	}
	return connect.NewResponse(resp), nil
}

func (s *AuthenticationServer) FinishPasskeyRegistration(ctx context.Context, req *connect.Request[v1.FinishPasskeyRegistrationRequest]) (*connect.Response[v1.FinishPasskeyRegistrationResponse], error) {
	input := application.FinishPasskeyRegistrationInput{
		FlowID:                  req.Msg.GetFlowId(),
		AttestationResponseJSON: req.Msg.GetAttestationResponseJson(),
	}
	out, err := s.service.FinishPasskeyRegistration(ctx, input)
	if err != nil {
		return nil, err
	}
	resp := &v1.FinishPasskeyRegistrationResponse{
		Passkey: toProtoPasskey(out.Passkey),
	}
	return connect.NewResponse(resp), nil
}

func (s *AuthenticationServer) BeginPasskeyLogin(ctx context.Context, req *connect.Request[v1.BeginPasskeyLoginRequest]) (*connect.Response[v1.BeginPasskeyLoginResponse], error) {
	md := meta.GetMeta(ctx)
	input := application.BeginPasskeyLoginInput{
		IPAddress: ip,
		UserAgent: ua,
	}
	if req.Msg.Email != nil {
		input.Email = req.Msg.Email
	}
	if req.Msg.FlowId != nil {
		input.FlowID = req.Msg.FlowId
	}
	out, err := s.service.BeginPasskeyLogin(ctx, input)
	if err != nil {
		return nil, err
	}
	resp := &v1.BeginPasskeyLoginResponse{
		RequestOptionsJson: out.RequestOptionsJSON,
		FlowId:             out.FlowID,
		Flow:               toProtoAuthFlow(out.Flow),
	}
	return connect.NewResponse(resp), nil
}

func (s *AuthenticationServer) FinishPasskeyLogin(ctx context.Context, req *connect.Request[v1.FinishPasskeyLoginRequest]) (*connect.Response[v1.FinishPasskeyLoginResponse], error) {
	md := meta.GetMeta(ctx)
	input := application.FinishPasskeyLoginInput{
		FlowID:                req.Msg.GetFlowId(),
		AssertionResponseJSON: req.Msg.GetAssertionResponseJson(),
		IPAddress:             ip,
		UserAgent:             ua,
	}
	out, err := s.service.FinishPasskeyLogin(ctx, input)
	if err != nil {
		return nil, err
	}
	expiresAt := timestamppb.New(out.Session.ExpiresAt)
	expiresIn := int64(out.Session.ExpiresAt.Sub(out.Session.CreatedAt).Seconds())
	resp := &v1.FinishPasskeyLoginResponse{
		Token:   toProtoToken(out.Token, out.RefreshToken, expiresAt, expiresIn),
		Session: toProtoSession(out.Session, true),
		User:    toProtoUser(out.User),
	}
	return connect.NewResponse(resp), nil
}
*/
