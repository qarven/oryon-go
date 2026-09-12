package application

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	"github.com/qarven/oryon-go/internal/identity/domain"
	"github.com/qarven/oryon-go/internal/pkg/goerror"
)

type VerifyEmailInput struct {
	VerificationID int64  `validate:"required"`
	Code           string `validate:"required"`
	Meta           MetaInput
}

type VerifyEmailOutput struct {
	User  domain.User
	Email *domain.UserEmail
	Phone *domain.UserPhoneNumber
}

// VerifyEmail completes a pending registration. The OTP proves ownership of
// the identifier, so the user row is created here — atomically with contact
// rows, credential, flow completion, and challenge consumption. Clients call
// Login afterwards to obtain tokens.
func (a *Application) VerifyEmail(ctx context.Context, input VerifyEmailInput) (*VerifyEmailOutput, error) {
	ctx, span := a.ins.Tracer("identity.application").Start(ctx, "VerifyEmail")
	defer span.End()

	if err := a.validator.Validate(input); err != nil {
		return nil, goerror.NewInvalidInput(err)
	}

	now := a.clock.Now()

	challenge, err := a.repo.GetVerificationChallengeByID(ctx, input.VerificationID)
	if errors.Is(err, domain.ErrVerificationNotFound) {
		return nil, goerror.NewBusiness("verification not found", goerror.CodeNotFound)
	}

	if err != nil {
		slog.ErrorContext(ctx, "failed to get verification challenge", "error", err)
		return nil, goerror.NewServer(err)
	}

	if challenge.FlowID == nil {
		return nil, goerror.NewBusiness("verification challenge is not linked to a registration", goerror.CodeInvalidInput)
	}

	flow, err := a.repo.GetAuthFlowByID(ctx, *challenge.FlowID)
	if errors.Is(err, domain.ErrAuthFlowNotFound) {
		return nil, goerror.NewBusiness("registration flow not found", goerror.CodeNotFound)
	}

	if err != nil {
		slog.ErrorContext(ctx, "failed to get auth flow", "error", err)
		return nil, goerror.NewServer(err)
	}

	if flow.FlowType != domain.AuthFlowTypeRegistration {
		return nil, goerror.NewBusiness("verification challenge is not for registration", goerror.CodeInvalidInput)
	}

	if flow.IsExpired(now) {
		return nil, goerror.NewBusiness("registration expired, please register again", goerror.CodeInvalidInput)
	}

	if flow.CompletedAt != nil || flow.FlowState.IsTerminal() {
		return nil, goerror.NewBusiness("registration already completed", goerror.CodeInvalidInput)
	}

	if err := challenge.CanAttempt(now); err != nil {
		switch {
		case errors.Is(err, domain.ErrVerificationExpired):
			return nil, goerror.NewBusiness("verification expired, please register again", goerror.CodeInvalidInput)
		case errors.Is(err, domain.ErrVerificationConsumed):
			return nil, goerror.NewBusiness("verification already used", goerror.CodeInvalidInput)
		case errors.Is(err, domain.ErrVerificationAttemptsExceeded):
			return nil, goerror.NewBusiness("too many attempts", goerror.CodeTooManyRequest)
		default:
			return nil, goerror.NewBusiness(err.Error(), goerror.CodeInvalidInput)
		}
	}

	if !a.sha256.Verify(string(challenge.CodeHash), input.Code) {
		challenge.IncrementAttempts()

		if uErr := a.repo.UpdateVerificationChallenge(ctx, *challenge); uErr != nil {
			slog.ErrorContext(ctx, "failed to update verification challenge attempts", "error", uErr)
			return nil, goerror.NewServer(uErr)
		}

		slog.WarnContext(ctx, "invalid verification code")
		return nil, goerror.NewBusiness("invalid verification code", goerror.CodeUnauthorized)
	}

	pending, err := pendingRegistrationFromFlow(flow)
	if err != nil {
		return nil, goerror.NewInvalidInput(nil, "flow", err.Error())
	}

	var userEmail *domain.UserEmail
	var userPhone *domain.UserPhoneNumber

	switch challenge.Purpose {
	case domain.VerificationPurposeEmailVerification:
		if pending.Email == "" || !strings.EqualFold(pending.Email, challenge.Identifier) {
			return nil, goerror.NewBusiness("verification challenge does not match registration email", goerror.CodeInvalidInput)
		}

		if _, err := a.repo.GetUserEmailByEmail(ctx, pending.Email); err == nil {
			return nil, goerror.NewBusiness("email already registered", goerror.CodeConflict)
		} else if !errors.Is(err, domain.ErrEmailNotFound) {
			slog.ErrorContext(ctx, "failed to get user email by email", "error", err)
			return nil, goerror.NewServer(err)
		}

		userEmail = &domain.UserEmail{
			ID:         a.uid.Generate(),
			Email:      pending.Email,
			IsPrimary:  true,
			CreatedAt:  now,
			VerifiedAt: &now,
		}

		// A phone supplied alongside the email stays unverified until its own
		// challenge is verified (follow-up); it must not block creation.
		if pending.Phone != "" {
			if _, err := a.repo.GetUserPhoneByPhone(ctx, pending.Phone); err == nil {
				return nil, goerror.NewBusiness("phone already registered", goerror.CodeConflict)
			} else if !errors.Is(err, domain.ErrPhoneNotFound) {
				slog.ErrorContext(ctx, "failed to get user phone by phone number", "error", err)
				return nil, goerror.NewServer(err)
			}

			userPhone = &domain.UserPhoneNumber{
				ID:        a.uid.Generate(),
				Phone:     pending.Phone,
				CreatedAt: now,
			}
		}
	case domain.VerificationPurposePhoneVerification:
		if pending.Phone == "" || pending.Phone != challenge.Identifier {
			return nil, goerror.NewBusiness("verification challenge does not match registration phone", goerror.CodeInvalidInput)
		}

		if _, err := a.repo.GetUserPhoneByPhone(ctx, pending.Phone); err == nil {
			return nil, goerror.NewBusiness("phone already registered", goerror.CodeConflict)
		} else if !errors.Is(err, domain.ErrPhoneNotFound) {
			slog.ErrorContext(ctx, "failed to get user phone by phone number", "error", err)
			return nil, goerror.NewServer(err)
		}

		userPhone = &domain.UserPhoneNumber{
			ID:         a.uid.Generate(),
			Phone:      pending.Phone,
			CreatedAt:  now,
			VerifiedAt: &now,
		}
	default:
		return nil, goerror.NewBusiness("verification challenge is not for registration", goerror.CodeInvalidInput)
	}

	userID := a.uid.Generate()

	user := domain.User{
		ID:        userID,
		Status:    domain.UserStatusActive,
		Name:      pending.Name,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if userEmail != nil {
		userEmail.UserID = userID
	}

	if userPhone != nil {
		userPhone.UserID = userID
	}

	if err := challenge.Consume(now); err != nil {
		return nil, goerror.NewBusiness(err.Error(), goerror.CodeInvalidInput)
	}

	flow.FlowState = domain.AuthFlowStateCompleted
	flow.CompletedAt = &now

	data := CompleteRegistrationData{
		User:      user,
		UserEmail: userEmail,
		UserPhone: userPhone,
		PassCred: domain.PasswordCredential{
			UserID:            userID,
			Password:          pending.PasswordHash,
			PasswordChangedAt: now,
			CreatedAt:         now,
			UpdatedAt:         now,
		},
		Flow:      *flow,
		Challenge: *challenge,
	}

	if err := a.repo.CompleteRegistration(ctx, data); err != nil {
		if errors.Is(err, domain.ErrIdentifierConflict) {
			slog.WarnContext(ctx, "identifier taken during registration completion")
			return nil, goerror.NewBusiness("identifier already registered", goerror.CodeConflict)
		}

		slog.ErrorContext(ctx, "failed to complete registration", "error", err)
		return nil, goerror.NewServer(err)
	}

	meta := input.Meta
	if meta.IPAddress == "" && challenge.IPAddress != nil {
		meta.IPAddress = *challenge.IPAddress
	}

	a.logSecurityEvent(
		&userID,
		domain.SecurityEventTypeRegistrationCompleted,
		meta,
		map[string]any{"flow_id": flow.ID},
	)

	if userEmail != nil {
		a.logSecurityEvent(
			&userID,
			domain.SecurityEventTypeEmailVerified,
			meta,
			map[string]any{"email": userEmail.Email},
		)
	}

	return &VerifyEmailOutput{User: user, Email: userEmail, Phone: userPhone}, nil
}

type pendingRegistration struct {
	Name         string
	Email        string
	Phone        string
	PasswordHash string
}

// pendingRegistrationFromFlow extracts the Registration-stored payload from a
// flow context. The password hash is opaque here; it is persisted as-is.
func pendingRegistrationFromFlow(flow *domain.AuthFlow) (pendingRegistration, error) {
	if flow.Context == nil {
		return pendingRegistration{}, errors.New("registration data missing")
	}

	get := func(key string) string {
		v, _ := flow.Context[key].(string)
		return strings.TrimSpace(v)
	}

	out := pendingRegistration{
		Name:         get(regCtxName),
		Email:        strings.ToLower(get(regCtxEmail)),
		Phone:        get(regCtxPhone),
		PasswordHash: get(regCtxPasswordHash),
	}

	if out.Name == "" || out.PasswordHash == "" {
		return pendingRegistration{}, errors.New("registration data missing")
	}

	if out.Email == "" && out.Phone == "" {
		return pendingRegistration{}, errors.New("registration data missing")
	}

	return out, nil
}
