package application

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/qarven/oryon-go/internal/identity/domain"
	"github.com/qarven/oryon-go/internal/pkg/goerror"
)

type InitiatePasswordResetInput struct {
	Identifier string    `validate:"required"`
	Meta       MetaInput `validate:"required"`
}

type InitiatePasswordResetOutput struct{}

type EventPasswordResetData struct {
	Name     string `json:"name"`
	Token    string `json:"token"`
	Identity string `json:"identity"`
	Channel  string `json:"channel"` // email, phone
}

type resolvedPasswordResetUser struct {
	User       *domain.User
	Identifier string
	Channel    string
	Email      string
	Phone      string
}

func (a *Application) InitiatePasswordReset(
	ctx context.Context,
	input InitiatePasswordResetInput,
) (*InitiatePasswordResetOutput, error) {
	ctx, span := a.ins.Tracer("identity.application").Start(ctx, "InitiatePasswordReset")
	defer span.End()

	input.Identifier = strings.TrimSpace(input.Identifier)

	err := a.validator.Validate(input)
	if err != nil {
		return nil, goerror.NewInvalidInput(err)
	}

	resolved, err := a.resolvePasswordResetUser(ctx, input.Identifier)
	if goerror.IsNotFound(err) {
		a.securityEvent(domain.SecurityEventTypePasswordResetRequested).
			WithMeta(input.Meta).
			With("identifier", input.Identifier).
			With("user_found", false).
			Emit(ctx)

		return &InitiatePasswordResetOutput{}, nil
	}

	if err != nil {
		return nil, err
	}

	user := resolved.User
	identifier := resolved.Identifier
	channel := resolved.Channel

	err = a.checkVerificationRateLimit(ctx, resolved.Email, resolved.Phone, strings.TrimSpace(input.Meta.IPAddress))
	if err != nil {
		return nil, err
	}

	if !user.IsActive() {
		slog.WarnContext(ctx, "user status is not active", "user_id", user.ID)

		return &InitiatePasswordResetOutput{}, nil
	}

	challenge, err := a.issuePasswordResetChallenge(ctx, user, identifier, channel, input.Meta.IPAddress, a.clock.Now())
	if err != nil {
		return nil, err
	}

	a.securityEvent(domain.SecurityEventTypePasswordResetRequested).
		ForUser(&user.ID).
		WithMeta(input.Meta).
		With("verification_id", challenge.ID).
		With("identifier", identifier).
		Emit(ctx)

	return &InitiatePasswordResetOutput{}, nil
}

func (a *Application) resolvePasswordResetUser(
	ctx context.Context,
	identifier string,
) (*resolvedPasswordResetUser, error) {
	switch {
	case strings.Contains(identifier, "@"):
		return a.resolvePasswordResetByEmail(ctx, identifier)
	case rePhone.MatchString(identifier):
		return a.resolvePasswordResetByPhone(ctx, identifier)
	case reUsername.MatchString(identifier):
		return a.resolvePasswordResetByUsername(ctx, identifier)
	default:
		slog.WarnContext(ctx, "password reset identifier is not email, phone or username")

		return nil, goerror.NewBusiness("invalid identifier", goerror.CodeInvalidInput)
	}
}

func (a *Application) resolvePasswordResetByEmail(
	ctx context.Context,
	identifier string,
) (*resolvedPasswordResetUser, error) {
	email := strings.ToLower(identifier)

	emailRec, err := a.repo.GetUserEmailByEmail(ctx, email)
	if errors.Is(err, domain.ErrEmailNotFound) {
		slog.WarnContext(ctx, "password reset email not found")

		return nil, goerror.NewBusiness("account not found", goerror.CodeNotFound)
	}

	if err != nil {
		slog.ErrorContext(ctx, "failed to get user email by email", "error", err)

		return nil, goerror.NewServer(err)
	}

	user, err := a.repo.GetUserByID(ctx, emailRec.UserID)
	if err != nil {
		slog.ErrorContext(ctx, "failed to get user by id", "user_id", emailRec.UserID, "error", err)

		return nil, goerror.NewServer(err)
	}

	if user.IsDeleted() {
		slog.WarnContext(ctx, "password reset user is deleted")

		return nil, goerror.NewBusiness("account not found", goerror.CodeNotFound)
	}

	return &resolvedPasswordResetUser{
		User:       user,
		Identifier: emailRec.Email,
		Channel:    channelEmail,
		Email:      emailRec.Email,
	}, nil
}

func (a *Application) resolvePasswordResetByPhone(
	ctx context.Context,
	identifier string,
) (*resolvedPasswordResetUser, error) {
	phoneRec, err := a.repo.GetUserPhoneByPhone(ctx, identifier)
	if errors.Is(err, domain.ErrPhoneNotFound) {
		slog.WarnContext(ctx, "password reset phone not found")

		return nil, goerror.NewBusiness("account not found", goerror.CodeNotFound)
	}

	if err != nil {
		slog.ErrorContext(ctx, "failed to get user phone by phone", "error", err)

		return nil, goerror.NewServer(err)
	}

	user, err := a.repo.GetUserByID(ctx, phoneRec.UserID)
	if err != nil {
		slog.ErrorContext(ctx, "failed to get user by id", "user_id", phoneRec.UserID, "error", err)

		return nil, goerror.NewServer(err)
	}

	if user.IsDeleted() {
		slog.WarnContext(ctx, "password reset user is deleted")

		return nil, goerror.NewBusiness("account not found", goerror.CodeNotFound)
	}

	return &resolvedPasswordResetUser{
		User:       user,
		Identifier: phoneRec.Phone,
		Channel:    channelPhone,
		Phone:      phoneRec.Phone,
	}, nil
}

func (a *Application) resolvePasswordResetByUsername(
	ctx context.Context,
	identifier string,
) (*resolvedPasswordResetUser, error) {
	user, err := a.repo.GetUserByUsername(ctx, identifier)
	if errors.Is(err, domain.ErrUserNotFound) {
		slog.WarnContext(ctx, "password reset user not found by username")

		return nil, goerror.NewBusiness("account not found", goerror.CodeNotFound)
	}

	if err != nil {
		slog.ErrorContext(ctx, "failed to get user by username", "error", err)

		return nil, goerror.NewServer(err)
	}

	if user.IsDeleted() {
		slog.WarnContext(ctx, "password reset user is deleted")

		return nil, goerror.NewBusiness("account not found", goerror.CodeNotFound)
	}

	emailRec, err := a.repo.GetPrimaryUserEmailByUserID(ctx, user.ID)
	if errors.Is(err, domain.ErrPrimaryEmailNotFound) {
		slog.WarnContext(ctx, "password reset primary email not found", "user_id", user.ID)

		return nil, goerror.NewBusiness("account not found", goerror.CodeNotFound)
	}

	if err != nil {
		slog.ErrorContext(ctx, "failed to get primary email by user id", "user_id", user.ID, "error", err)

		return nil, goerror.NewServer(err)
	}

	return &resolvedPasswordResetUser{
		User:       user,
		Identifier: emailRec.Email,
		Channel:    channelEmail,
		Email:      emailRec.Email,
	}, nil
}

func (a *Application) issuePasswordResetChallenge(
	ctx context.Context,
	user *domain.User,
	identifier, channel, ipAddress string,
	now time.Time,
) (*domain.VerificationChallenge, error) {
	rawCode, err := generate32RandomString()
	if err != nil {
		slog.ErrorContext(ctx, "failed to generate verification code", "user_id", user.ID, "error", err)

		return nil, goerror.NewServer(err)
	}

	codeHash, err := a.sha256.Hash(rawCode)
	if err != nil {
		slog.ErrorContext(ctx, "failed to hash verification code", "user_id", user.ID, "error", err)

		return nil, goerror.NewServer(err)
	}

	challenge := &domain.VerificationChallenge{
		ID:          domain.IDFrom(a.uuid.Generate()),
		UserID:      &user.ID,
		FlowID:      nil,
		Identifier:  identifier,
		Purpose:     domain.VerificationPurposePasswordReset,
		CodeHash:    codeHash,
		Attempts:    0,
		MaxAttempts: int16(a.config.GetInt("modules.identity.verification.max_attempts")),
		IPAddress:   &ipAddress,
		ExpiresAt:   now.Add(a.config.GetMinute("modules.identity.verification.ttl")),
		CreatedAt:   now,
	}

	err = a.repo.CreatePasswordResetChallenge(ctx, *challenge)
	if err != nil {
		slog.ErrorContext(ctx, "failed to create password reset challenge", "user_id", user.ID, "error", err)

		return nil, goerror.NewServer(err)
	}

	vid := fmt.Sprintf("%s-%s", strings.ReplaceAll(challenge.ID.String(), "-", ""), rawCode)

	err = a.event.PublishEventPasswordReset(ctx, EventPasswordResetData{
		Name:     user.Name,
		Channel:  channel,
		Identity: identifier,
		Token:    base64.RawURLEncoding.EncodeToString([]byte(vid)),
	})
	if err != nil {
		slog.ErrorContext(ctx, "failed to publish password reset event",
			"user_id", user.ID,
			"identifier", identifier,
			"channel", channel,
			"error", err,
		)

		return nil, goerror.NewServer(err)
	}

	return challenge, nil
}
