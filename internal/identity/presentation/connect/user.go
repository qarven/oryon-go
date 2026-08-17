package connect

import (
	"context"

	"connectrpc.com/connect"
	v1 "github.com/qarven/mono/gen/go/oryon/identity/v1"
	"github.com/qarven/mono/gen/go/oryon/identity/v1/identityconnect"
	"github.com/qarven/oryon-go/internal/identity/application"
)

type UserService interface {
	GetCurrentUser(ctx context.Context, input application.GetCurrentUserInput) (*application.GetCurrentUserOutput, error)
	UpdateCurrentUser(ctx context.Context, input application.UpdateCurrentUserInput) (*application.UpdateCurrentUserOutput, error)
	ListEmails(ctx context.Context, input application.ListEmailsInput) (*application.ListEmailsOutput, error)
	AddEmail(ctx context.Context, input application.AddEmailInput) (*application.AddEmailOutput, error)
	RemoveEmail(ctx context.Context, input application.RemoveEmailInput) (*application.RemoveEmailOutput, error)
	SetPrimaryEmail(ctx context.Context, input application.SetPrimaryEmailInput) (*application.SetPrimaryEmailOutput, error)
}

type UserServer struct {
	identityconnect.UnimplementedUserServiceHandler
	service UserService
}

func NewUserServer(service UserService) *UserServer {
	return &UserServer{service: service}
}

func (s *UserServer) GetCurrentUser(ctx context.Context, req *connect.Request[v1.GetCurrentUserRequest]) (*connect.Response[v1.GetCurrentUserResponse], error) {
	out, err := s.service.GetCurrentUser(ctx, application.GetCurrentUserInput{})
	if err != nil {
		return nil, err
	}
	var emails []*v1.UserEmail
	for _, e := range out.Emails {
		emails = append(emails, toProtoUserEmail(e))
	}
	var phones []*v1.UserPhoneNumber
	for _, p := range out.PhoneNumbers {
		phones = append(phones, toProtoUserPhone(p))
	}
	var idents []*v1.Identity
	for _, id := range out.Identities {
		idents = append(idents, toProtoIdentity(id))
	}
	resp := &v1.GetCurrentUserResponse{
		User:         toProtoUser(out.User),
		Emails:       emails,
		PhoneNumbers: phones,
		Identities:   idents,
	}
	return connect.NewResponse(resp), nil
}

func (s *UserServer) UpdateCurrentUser(ctx context.Context, req *connect.Request[v1.UpdateCurrentUserRequest]) (*connect.Response[v1.UpdateCurrentUserResponse], error) {
	input := application.UpdateCurrentUserInput{}
	if req.Msg.Name != nil {
		input.Name = req.Msg.Name
	}
	if req.Msg.AvatarUrl != nil {
		input.AvatarURL = req.Msg.AvatarUrl
	}
	if req.Msg.UpdateMask != nil {
		input.UpdateMask = req.Msg.UpdateMask.GetPaths()
	}
	out, err := s.service.UpdateCurrentUser(ctx, input)
	if err != nil {
		return nil, err
	}
	resp := &v1.UpdateCurrentUserResponse{
		User: toProtoUser(out.User),
	}
	return connect.NewResponse(resp), nil
}

func (s *UserServer) ListEmails(ctx context.Context, req *connect.Request[v1.ListEmailsRequest]) (*connect.Response[v1.ListEmailsResponse], error) {
	input := application.ListEmailsInput{
		PageSize:       req.Msg.GetPageSize(),
		PageToken:      req.Msg.GetPageToken(),
		IncludeDeleted: req.Msg.GetIncludeDeleted(),
	}
	out, err := s.service.ListEmails(ctx, input)
	if err != nil {
		return nil, err
	}
	var protos []*v1.UserEmail
	for _, e := range out.Emails {
		protos = append(protos, toProtoUserEmail(e))
	}
	resp := &v1.ListEmailsResponse{
		Emails:        protos,
		NextPageToken: out.NextPageToken,
	}
	return connect.NewResponse(resp), nil
}

func (s *UserServer) AddEmail(ctx context.Context, req *connect.Request[v1.AddEmailRequest]) (*connect.Response[v1.AddEmailResponse], error) {
	input := application.AddEmailInput{
		Email:            req.Msg.GetEmail(),
		SendVerification: req.Msg.GetSendVerification(),
	}
	out, err := s.service.AddEmail(ctx, input)
	if err != nil {
		return nil, err
	}
	resp := &v1.AddEmailResponse{
		Email:                toProtoUserEmail(out.Email),
		VerificationRequired: out.VerificationRequired,
		VerificationId:       out.VerificationID,
	}
	return connect.NewResponse(resp), nil
}

func (s *UserServer) RemoveEmail(ctx context.Context, req *connect.Request[v1.RemoveEmailRequest]) (*connect.Response[v1.RemoveEmailResponse], error) {
	input := application.RemoveEmailInput{
		EmailID: req.Msg.GetEmailId(),
	}
	_, err := s.service.RemoveEmail(ctx, input)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&v1.RemoveEmailResponse{}), nil
}

func (s *UserServer) SetPrimaryEmail(ctx context.Context, req *connect.Request[v1.SetPrimaryEmailRequest]) (*connect.Response[v1.SetPrimaryEmailResponse], error) {
	input := application.SetPrimaryEmailInput{
		EmailID: req.Msg.GetEmailId(),
	}
	out, err := s.service.SetPrimaryEmail(ctx, input)
	if err != nil {
		return nil, err
	}
	resp := &v1.SetPrimaryEmailResponse{
		Email: toProtoUserEmail(out.Email),
	}
	return connect.NewResponse(resp), nil
}
