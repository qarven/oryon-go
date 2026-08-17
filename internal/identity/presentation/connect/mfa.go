package connect

import (
	"context"

	"connectrpc.com/connect"
	v1 "github.com/qarven/mono/gen/go/oryon/identity/v1"
	"github.com/qarven/mono/gen/go/oryon/identity/v1/identityconnect"
	"github.com/qarven/oryon-go/internal/identity/application"
	"github.com/qarven/oryon-go/internal/identity/domain"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type MfaService interface {
	ListFactors(ctx context.Context, input application.ListFactorsInput) (*application.ListFactorsOutput, error)
	BeginTotpSetup(ctx context.Context, input application.BeginTotpSetupInput) (*application.BeginTotpSetupOutput, error)
	ConfirmTotpSetup(ctx context.Context, input application.ConfirmTotpSetupInput) (*application.ConfirmTotpSetupOutput, error)
	DisableTotp(ctx context.Context, input application.DisableTotpInput) (*application.DisableTotpOutput, error)
	GenerateRecoveryCodes(ctx context.Context, input application.GenerateRecoveryCodesInput) (*application.GenerateRecoveryCodesOutput, error)
	RevokeRecoveryCodes(ctx context.Context, input application.RevokeRecoveryCodesInput) (*application.RevokeRecoveryCodesOutput, error)
}

type MfaServer struct {
	identityconnect.UnimplementedMfaServiceHandler
	service MfaService
}

func NewMfaServer(service MfaService) *MfaServer {
	return &MfaServer{service: service}
}

func (s *MfaServer) ListFactors(ctx context.Context, req *connect.Request[v1.ListFactorsRequest]) (*connect.Response[v1.ListFactorsResponse], error) {
	input := application.ListFactorsInput{
		IncludeRevoked: req.Msg.GetIncludeRevoked(),
	}
	out, err := s.service.ListFactors(ctx, input)
	if err != nil {
		return nil, err
	}
	var factors []*v1.MfaFactor
	for _, f := range out.Factors {
		factors = append(factors, toProtoMfaFactor(f))
	}
	var totps []*v1.TotpFactor
	for _, t := range out.TotpFactors {
		totps = append(totps, toProtoTotpFactor(t))
	}
	var passkeys []*v1.Passkey
	for _, p := range out.Passkeys {
		passkeys = append(passkeys, toProtoPasskey(p))
	}
	resp := &v1.ListFactorsResponse{
		Factors:              factors,
		TotpFactors:          totps,
		Passkeys:             passkeys,
		BackupCodesRemaining: out.BackupCodesRemaining,
	}
	return connect.NewResponse(resp), nil
}

func (s *MfaServer) BeginTotpSetup(ctx context.Context, req *connect.Request[v1.BeginTotpSetupRequest]) (*connect.Response[v1.BeginTotpSetupResponse], error) {
	input := application.BeginTotpSetupInput{
		Name:      req.Msg.GetName(),
		Algorithm: domain.TotpAlgorithm(req.Msg.GetAlgorithm()),
		Digits:    req.Msg.GetDigits(),
		Period:    req.Msg.GetPeriod(),
	}
	if req.Msg.Issuer != nil {
		input.Issuer = req.Msg.Issuer
	}
	out, err := s.service.BeginTotpSetup(ctx, input)
	if err != nil {
		return nil, err
	}
	resp := &v1.BeginTotpSetupResponse{
		Factor:     toProtoMfaFactor(out.Factor),
		TotpFactor: toProtoTotpFactor(out.TotpFactor),
		Secret:     out.Secret,
		Uri:        out.URI,
	}
	return connect.NewResponse(resp), nil
}

func (s *MfaServer) ConfirmTotpSetup(ctx context.Context, req *connect.Request[v1.ConfirmTotpSetupRequest]) (*connect.Response[v1.ConfirmTotpSetupResponse], error) {
	input := application.ConfirmTotpSetupInput{
		FactorID: req.Msg.GetFactorId(),
		Code:     req.Msg.GetCode(),
	}
	out, err := s.service.ConfirmTotpSetup(ctx, input)
	if err != nil {
		return nil, err
	}
	resp := &v1.ConfirmTotpSetupResponse{
		Factor: toProtoMfaFactor(out.Factor),
	}
	return connect.NewResponse(resp), nil
}

func (s *MfaServer) DisableTotp(ctx context.Context, req *connect.Request[v1.DisableTotpRequest]) (*connect.Response[v1.DisableTotpResponse], error) {
	input := application.DisableTotpInput{
		FactorID: req.Msg.GetFactorId(),
	}
	if req.Msg.CurrentPassword != nil {
		input.CurrentPassword = req.Msg.CurrentPassword
	}
	_, err := s.service.DisableTotp(ctx, input)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&v1.DisableTotpResponse{}), nil
}

func (s *MfaServer) GenerateRecoveryCodes(ctx context.Context, req *connect.Request[v1.GenerateRecoveryCodesRequest]) (*connect.Response[v1.GenerateRecoveryCodesResponse], error) {
	count := req.Msg.GetCount()
	if count == 0 {
		count = 10
	}
	input := application.GenerateRecoveryCodesInput{
		Count: count,
	}
	out, err := s.service.GenerateRecoveryCodes(ctx, input)
	if err != nil {
		return nil, err
	}
	resp := &v1.GenerateRecoveryCodesResponse{
		Codes:     out.Codes,
		Count:     out.Count,
		CreatedAt: timestamppb.New(out.CreatedAt),
		ExpiresAt: timestamppb.New(out.ExpiresAt),
	}
	return connect.NewResponse(resp), nil
}

func (s *MfaServer) RevokeRecoveryCodes(ctx context.Context, req *connect.Request[v1.RevokeRecoveryCodesRequest]) (*connect.Response[v1.RevokeRecoveryCodesResponse], error) {
	out, err := s.service.RevokeRecoveryCodes(ctx, application.RevokeRecoveryCodesInput{})
	if err != nil {
		return nil, err
	}
	resp := &v1.RevokeRecoveryCodesResponse{
		RevokedCount: out.RevokedCount,
	}
	return connect.NewResponse(resp), nil
}
