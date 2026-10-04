package application

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/qarven/oryon-go/internal/identity/domain"
	"github.com/qarven/oryon-go/internal/pkg/goerror"
)

// ===== Password reset: initiate =====

const (
	passwordResetChannelEmail = "email"
	passwordResetChannelPhone = "phone"
)

type InitiatePasswordResetInput struct {
	Identifier string    `validate:"required"`
	Meta       MetaInput `validate:"required"`
}

type InitiatePasswordResetOutput struct {
	Challenge domain.VerificationChallenge
}

type EventPasswordResetData struct {
	Name     string `json:"name"`
	Code     string `json:"code"`
	Identity string `json:"identity"`
	Channel  string `json:"channel"` // email, phone
}

type passwordResetChallengeData struct {
	UserID     int64
	Identifier string
	IPAddress  string
	Now        time.Time
}

func (a *Application) InitiatePasswordReset(
	ctx context.Context,
	input InitiatePasswordResetInput,
) (*InitiatePasswordResetOutput, error) {
	ctx, span := a.ins.Tracer("identity.application").Start(ctx, "InitiatePasswordReset")
	defer span.End()

	input.Identifier = strings.TrimSpace(input.Identifier)

	validateErr := a.validator.Validate(input)
	if validateErr != nil {
		return nil, goerror.NewInvalidInput(validateErr)
	}

	resolved, err := a.resolvePasswordResetUser(ctx, input.Identifier)
	if goerror.IsNotFound(err) {
		a.logSecurityEvent(ctx, nil, domain.SecurityEventTypePasswordResetRequested, input.Meta,
			map[string]any{securityEventIdentifierKey: input.Identifier, "user_found": false})

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

	err = ensureUserCanAuthenticate(ctx, user)
	if err != nil {
		return nil, err
	}

	challenge, err := a.issuePasswordResetChallenge(ctx, user, identifier, channel, input.Meta.IPAddress, a.clock.Now())
	if err != nil {
		return nil, err
	}

	a.logSecurityEvent(
		ctx,
		&user.ID,
		domain.SecurityEventTypePasswordResetRequested,
		input.Meta,
		map[string]any{securityEventVerificationIDKey: challenge.ID, securityEventIdentifierKey: identifier},
	)

	return &InitiatePasswordResetOutput{Challenge: *challenge}, nil
}

// issuePasswordResetChallenge creates, persists and publishes a fresh
// password-reset challenge for the user.
func (a *Application) issuePasswordResetChallenge(
	ctx context.Context,
	user *domain.User,
	identifier, channel, ipAddress string,
	now time.Time,
) (*domain.VerificationChallenge, error) {
	challenge, rawCode, err := a.newPasswordResetChallenge(ctx, passwordResetChallengeData{
		UserID:     user.ID,
		Identifier: identifier,
		IPAddress:  ipAddress,
		Now:        now,
	})
	if err != nil {
		return nil, err
	}

	err = a.repo.CreatePasswordResetChallenge(ctx, *challenge)
	if err != nil {
		slog.ErrorContext(ctx, "failed to create password reset challenge", "error", err)

		return nil, goerror.NewServer(err)
	}

	err = a.event.PublishEventPasswordReset(ctx, EventPasswordResetData{
		Name:     user.Name,
		Channel:  channel,
		Identity: identifier,
		Code:     rawCode,
	})
	if err != nil {
		slog.ErrorContext(ctx, "failed to publish password reset event", "error", err)

		return nil, goerror.NewServer(err)
	}

	return challenge, nil
}

func (a *Application) newPasswordResetChallenge(
	ctx context.Context,
	data passwordResetChallengeData,
) (*domain.VerificationChallenge, string, error) {
	rawCode, err := generate6DigitCode()
	if err != nil {
		slog.ErrorContext(ctx, "failed to generate verification code", "error", err)

		return nil, "", goerror.NewServer(err)
	}

	codeHash, err := a.sha256.Hash(rawCode)
	if err != nil {
		slog.ErrorContext(ctx, "failed to hash verification code", "error", err)

		return nil, "", goerror.NewServer(err)
	}

	challenge := &domain.VerificationChallenge{
		ID:          a.uid.Generate(),
		UserID:      &data.UserID,
		FlowID:      nil,
		Identifier:  data.Identifier,
		Purpose:     domain.VerificationPurposePasswordReset,
		CodeHash:    codeHash,
		Attempts:    0,
		MaxAttempts: int16(a.config.GetInt("modules.identity.verification.max_attempts")),
		IPAddress:   &data.IPAddress,
		ExpiresAt:   data.Now.Add(a.config.GetMinute("modules.identity.verification.ttl")),
		CreatedAt:   data.Now,
	}

	return challenge, rawCode, nil
}

// resolvedPasswordResetUser carries the user plus the delivery
// identifier, channel and rate-limit keys for a password-reset request.
type resolvedPasswordResetUser struct {
	User       *domain.User
	Identifier string
	Channel    string
	Email      string
	Phone      string
}

// resolvePasswordResetUser finds the user and the delivery identifier/channel
// for a password-reset request. Email and phone resolve directly; username
// resolves to the user's primary email.
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
		slog.ErrorContext(ctx, "failed to get user by id", "error", err)

		return nil, goerror.NewServer(err)
	}

	if user.IsDeleted() {
		slog.WarnContext(ctx, "password reset user is deleted")

		return nil, goerror.NewBusiness("account not found", goerror.CodeNotFound)
	}

	return &resolvedPasswordResetUser{
		User: user, Identifier: emailRec.Email, Channel: passwordResetChannelEmail, Email: emailRec.Email,
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
		slog.ErrorContext(ctx, "failed to get user by id", "error", err)

		return nil, goerror.NewServer(err)
	}

	if user.IsDeleted() {
		slog.WarnContext(ctx, "password reset user is deleted")

		return nil, goerror.NewBusiness("account not found", goerror.CodeNotFound)
	}

	return &resolvedPasswordResetUser{
		User: user, Identifier: phoneRec.Phone, Channel: passwordResetChannelPhone, Phone: phoneRec.Phone,
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
		slog.WarnContext(ctx, "password reset primary email not found")

		return nil, goerror.NewBusiness("account not found", goerror.CodeNotFound)
	}

	if err != nil {
		slog.ErrorContext(ctx, "failed to get primary email by user id", "error", err)

		return nil, goerror.NewServer(err)
	}

	return &resolvedPasswordResetUser{
		User: user, Identifier: emailRec.Email, Channel: passwordResetChannelEmail, Email: emailRec.Email,
	}, nil
}

// ===== Password reset: complete =====

type CompletePasswordResetInput struct {
	VerificationID int64     `validate:"required"`
	Code           string    `validate:"required"`
	NewPassword    string    `validate:"required,password"`
	Meta           MetaInput `validate:"required"`
}

type CompletePasswordResetOutput struct {
	User *domain.User
}

// CompletePasswordResetData carries the atomic password update.
type CompletePasswordResetData struct {
	UserID    int64
	Password  string
	ChangedAt time.Time
	UpdatedAt time.Time
	Challenge domain.VerificationChallenge
}

func (a *Application) CompletePasswordReset(
	ctx context.Context,
	input CompletePasswordResetInput,
) (*CompletePasswordResetOutput, error) {
	ctx, span := a.ins.Tracer("identity.application").Start(ctx, "CompletePasswordReset")
	defer span.End()

	input.Code = strings.TrimSpace(input.Code)

	validateErr := a.validator.Validate(input)
	if validateErr != nil {
		return nil, goerror.NewInvalidInput(validateErr)
	}

	now := a.clock.Now()

	challenge, err := a.loadPasswordResetChallenge(ctx, input.VerificationID, now)
	if err != nil {
		return nil, err
	}

	err = a.verifyPasswordResetCode(ctx, challenge, input.Code, now)
	if err != nil {
		return nil, err
	}

	user, err := a.loadPasswordResetUser(ctx, *challenge.UserID)
	if err != nil {
		return nil, err
	}

	hash, err := a.argon2id.Hash(input.NewPassword)
	if err != nil {
		slog.ErrorContext(ctx, "failed to hash new password", "error", err)

		return nil, goerror.NewServer(err)
	}

	err = challenge.Consume(now)
	if err != nil {
		return nil, goerror.NewBusiness(err.Error(), goerror.CodeInvalidInput)
	}

	err = a.persistCompletePasswordReset(ctx, user, string(hash), *challenge, now)
	if err != nil {
		return nil, err
	}

	user.UpdatedAt = now

	a.logSecurityEvent(
		ctx,
		&user.ID,
		domain.SecurityEventTypePasswordResetCompleted,
		input.Meta,
		map[string]any{securityEventVerificationIDKey: challenge.ID},
	)

	return &CompletePasswordResetOutput{User: user}, nil
}

// persistCompletePasswordReset atomically updates the password and consumes
// the verification challenge.
func (a *Application) persistCompletePasswordReset(
	ctx context.Context,
	user *domain.User,
	password string,
	challenge domain.VerificationChallenge,
	now time.Time,
) error {
	err := a.repo.CompletePasswordReset(ctx, CompletePasswordResetData{
		UserID:    user.ID,
		Password:  password,
		ChangedAt: now,
		UpdatedAt: now,
		Challenge: challenge,
	})
	if err != nil {
		slog.ErrorContext(ctx, "failed to complete password reset", "error", err)

		return goerror.NewServer(err)
	}

	return nil
}

// loadPasswordResetUser returns the target user, rejecting missing or
// deleted accounts.
func (a *Application) loadPasswordResetUser(ctx context.Context, userID int64) (*domain.User, error) {
	user, err := a.repo.GetUserByID(ctx, userID)
	if errors.Is(err, domain.ErrUserNotFound) {
		slog.WarnContext(ctx, "password reset user not found")

		return nil, goerror.NewBusiness("invalid or expired verification", goerror.CodeNotFound)
	}

	if err != nil {
		slog.ErrorContext(ctx, "failed to get user by id", "error", err)

		return nil, goerror.NewServer(err)
	}

	if user.IsDeleted() {
		slog.WarnContext(ctx, "password reset user is deleted")

		return nil, goerror.NewBusiness("invalid or expired verification", goerror.CodeNotFound)
	}

	return user, nil
}

// loadPasswordResetChallenge returns the challenge ensuring it is for
// password reset and can still be attempted.
func (a *Application) loadPasswordResetChallenge(
	ctx context.Context,
	verificationID int64,
	now time.Time,
) (*domain.VerificationChallenge, error) {
	challenge, err := a.repo.GetVerificationChallengeByID(ctx, verificationID)
	if errors.Is(err, domain.ErrVerificationNotFound) {
		return nil, goerror.NewBusiness("invalid or expired verification", goerror.CodeNotFound)
	}

	if err != nil {
		slog.ErrorContext(ctx, "failed to get verification challenge", "error", err)

		return nil, goerror.NewServer(err)
	}

	if challenge.Purpose != domain.VerificationPurposePasswordReset {
		return nil, goerror.NewBusiness("invalid or expired verification", goerror.CodeNotFound)
	}

	if challenge.UserID == nil {
		return nil, goerror.NewBusiness("invalid or expired verification", goerror.CodeNotFound)
	}

	err = challenge.CanAttempt(now)
	if err != nil {
		slog.WarnContext(ctx, "password reset challenge cannot be attempted", "error", err)

		return nil, goerror.NewBusiness("invalid or expired verification", goerror.CodeNotFound)
	}

	return challenge, nil
}

// verifyPasswordResetCode validates the supplied code, persisting the
// attempt counter on mismatch.
func (a *Application) verifyPasswordResetCode(
	ctx context.Context,
	challenge *domain.VerificationChallenge,
	code string,
	now time.Time,
) error {
	_ = now

	if !a.sha256.Verify(string(challenge.CodeHash), code) {
		challenge.IncrementAttempts()

		updateErr := a.repo.UpdateVerificationChallenge(ctx, *challenge)
		if updateErr != nil {
			slog.ErrorContext(ctx, "failed to update verification challenge attempts", "error", updateErr)

			return goerror.NewServer(updateErr)
		}

		slog.WarnContext(ctx, "invalid password reset code")

		return goerror.NewBusiness("invalid verification code", goerror.CodeUnauthorized)
	}

	return nil
}

// ===== Password reset: resend code =====

type ResendPasswordResetCodeInput struct {
	VerificationID int64     `validate:"required"`
	Meta           MetaInput `validate:"required"`
}

type ResendPasswordResetCodeOutput struct {
	Challenge domain.VerificationChallenge
}

func (a *Application) ResendPasswordResetCode(
	ctx context.Context,
	input ResendPasswordResetCodeInput,
) (*ResendPasswordResetCodeOutput, error) {
	ctx, span := a.ins.Tracer("identity.application").Start(ctx, "ResendPasswordResetCode")
	defer span.End()

	validateErr := a.validator.Validate(input)
	if validateErr != nil {
		return nil, goerror.NewInvalidInput(validateErr)
	}

	now := a.clock.Now()

	prev, user, err := a.loadResendPasswordResetTarget(ctx, input.VerificationID)
	if err != nil {
		return nil, err
	}

	email, phone := passwordResetRateLimitKeys(prev.Identifier)

	err = a.checkVerificationRateLimit(ctx, email, phone, strings.TrimSpace(input.Meta.IPAddress))
	if err != nil {
		return nil, err
	}

	channel := passwordResetChannelEmail
	if rePhone.MatchString(prev.Identifier) {
		channel = passwordResetChannelPhone
	}

	challenge, err := a.issuePasswordResetChallenge(ctx, user, prev.Identifier, channel, input.Meta.IPAddress, now)
	if err != nil {
		return nil, err
	}

	a.logSecurityEvent(
		ctx,
		&user.ID,
		domain.SecurityEventTypePasswordResetRequested,
		input.Meta,
		map[string]any{
			securityEventVerificationIDKey: challenge.ID, securityEventIdentifierKey: prev.Identifier, "resend": true,
		},
	)

	return &ResendPasswordResetCodeOutput{Challenge: *challenge}, nil
}

// loadResendPasswordResetTarget validates the previous challenge and returns
// it together with its owning user.
func (a *Application) loadResendPasswordResetTarget(
	ctx context.Context,
	verificationID int64,
) (*domain.VerificationChallenge, *domain.User, error) {
	prev, err := a.repo.GetVerificationChallengeByID(ctx, verificationID)
	if errors.Is(err, domain.ErrVerificationNotFound) {
		return nil, nil, goerror.NewBusiness("invalid or expired verification", goerror.CodeNotFound)
	}

	if err != nil {
		slog.ErrorContext(ctx, "failed to get verification challenge", "error", err)

		return nil, nil, goerror.NewServer(err)
	}

	if prev.Purpose != domain.VerificationPurposePasswordReset {
		return nil, nil, goerror.NewBusiness("invalid or expired verification", goerror.CodeNotFound)
	}

	if prev.IsConsumed() {
		return nil, nil, goerror.NewBusiness("invalid or expired verification", goerror.CodeNotFound)
	}

	if prev.UserID == nil {
		return nil, nil, goerror.NewBusiness("invalid or expired verification", goerror.CodeNotFound)
	}

	user, err := a.repo.GetUserByID(ctx, *prev.UserID)
	if errors.Is(err, domain.ErrUserNotFound) {
		return nil, nil, goerror.NewBusiness("invalid or expired verification", goerror.CodeNotFound)
	}

	if err != nil {
		slog.ErrorContext(ctx, "failed to get user by id", "error", err)

		return nil, nil, goerror.NewServer(err)
	}

	err = ensureUserCanAuthenticate(ctx, user)
	if err != nil {
		return nil, nil, err
	}

	return prev, user, nil
}

func passwordResetRateLimitKeys(identifier string) (string, string) {
	if strings.Contains(identifier, "@") {
		return strings.ToLower(identifier), ""
	}

	if rePhone.MatchString(identifier) {
		return "", identifier
	}

	return "", ""
}
