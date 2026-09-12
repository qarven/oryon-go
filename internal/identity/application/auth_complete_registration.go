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

type CompleteRegistrationInput struct {
	FlowID    int64     `validate:"required"`
	EmailCode *string   `validate:"required_without=PhoneCode"`
	PhoneCode *string   `validate:"required_without=EmailCode"`
	Meta      MetaInput `validate:"required"`
}

type CompleteRegistrationOutput struct {
	User *domain.User
}

func (a *Application) CompleteRegistration(ctx context.Context, input CompleteRegistrationInput) (*CompleteRegistrationOutput, error) {
	ctx, span := a.ins.Tracer("identity.application").Start(ctx, "CompleteRegistration")
	defer span.End()

	var emailCode, phoneCode string

	if input.EmailCode != nil {
		v := strings.TrimSpace(*input.EmailCode)
		input.EmailCode = &v
		emailCode = v
	}

	if input.PhoneCode != nil {
		v := strings.TrimSpace(*input.PhoneCode)
		input.PhoneCode = &v
		phoneCode = v
	}

	if err := a.validator.Validate(input); err != nil {
		return nil, goerror.NewInvalidInput(err)
	}

	flow, err := a.repo.GetAuthFlowByID(ctx, input.FlowID)
	if errors.Is(err, domain.ErrAuthFlowNotFound) {
		return nil, goerror.NewBusiness("registration flow not found", goerror.CodeNotFound)
	}

	if err != nil {
		slog.ErrorContext(ctx, "failed to get auth flow", "error", err)

		return nil, goerror.NewServer(err)
	}

	now := a.clock.Now()

	if flow.FlowType != domain.AuthFlowTypeRegistration {
		return nil, goerror.NewBusiness("flow is not for registration", goerror.CodeInvalidInput)
	}

	if flow.IsExpired(now) {
		return nil, goerror.NewBusiness("registration expired, please register again", goerror.CodeInvalidInput)
	}

	if flow.CompletedAt != nil || flow.FlowState.IsTerminal() {
		return nil, goerror.NewBusiness("registration already completed", goerror.CodeInvalidInput)
	}

	pending, err := pendingRegistrationFromFlow(flow)
	if err != nil {
		return nil, goerror.NewInvalidInput(nil, "flow", err.Error())
	}

	var emailChallenge, phoneChallenge *domain.VerificationChallenge

	if emailCode != "" {
		ch, err := a.verifyRegistrationChallenge(ctx, now, flow.ID, pending.Email, domain.VerificationPurposeEmailVerification, emailCode)
		if err != nil {
			return nil, err
		}

		emailChallenge = ch
	}

	if phoneCode != "" {
		ch, err := a.verifyRegistrationChallenge(ctx, now, flow.ID, pending.Phone, domain.VerificationPurposePhoneVerification, phoneCode)
		if err != nil {
			return nil, err
		}

		phoneChallenge = ch
	}

	// Pre-check uniqueness so a lost race surfaces as 409 instead of 500.
	// The persistence layer re-checks inside the transaction.
	if pending.Email != "" {
		if _, err := a.repo.GetUserEmailByEmail(ctx, pending.Email); err == nil {
			return nil, goerror.NewBusiness("email already registered", goerror.CodeConflict)
		} else if !errors.Is(err, domain.ErrEmailNotFound) {
			slog.ErrorContext(ctx, "failed to get user email by email", "error", err)

			return nil, goerror.NewServer(err)
		}
	}

	if pending.Phone != "" {
		if _, err := a.repo.GetUserPhoneByPhone(ctx, pending.Phone); err == nil {
			return nil, goerror.NewBusiness("phone already registered", goerror.CodeConflict)
		} else if !errors.Is(err, domain.ErrPhoneNotFound) {
			slog.ErrorContext(ctx, "failed to get user phone by phone number", "error", err)

			return nil, goerror.NewServer(err)
		}
	}

	userID := a.uid.Generate()

	user := domain.User{
		ID:        userID,
		Status:    domain.UserStatusActive,
		Name:      pending.Name,
		CreatedAt: now,
		UpdatedAt: now,
	}

	var userEmail *domain.UserEmail
	if pending.Email != "" {
		userEmail = &domain.UserEmail{
			ID:        a.uid.Generate(),
			UserID:    userID,
			Email:     pending.Email,
			IsPrimary: true,
			CreatedAt: now,
		}

		if emailChallenge != nil {
			userEmail.VerifiedAt = &now
		}
	}

	var userPhone *domain.UserPhoneNumber
	if pending.Phone != "" {
		userPhone = &domain.UserPhoneNumber{
			ID:        a.uid.Generate(),
			UserID:    userID,
			Phone:     pending.Phone,
			CreatedAt: now,
		}

		if phoneChallenge != nil {
			userPhone.VerifiedAt = &now
		}
	}

	primaryChallenge := emailChallenge
	if primaryChallenge == nil {
		primaryChallenge = phoneChallenge
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
		Challenge: *primaryChallenge,
	}

	if err := a.repo.CompleteRegistration(ctx, data); err != nil {
		if errors.Is(err, domain.ErrIdentifierConflict) {
			slog.WarnContext(ctx, "identifier taken during registration completion")

			return nil, goerror.NewBusiness("identifier already registered", goerror.CodeConflict)
		}

		slog.ErrorContext(ctx, "failed to complete registration", "error", err)

		return nil, goerror.NewServer(err)
	}

	// The persistence transaction consumes the primary challenge; when both
	// channels were verified, consume the second one as well. The user row
	// already exists at this point, so a failure here is cleanup only.
	if emailChallenge != nil && phoneChallenge != nil {
		err := a.repo.UpdateVerificationChallenge(ctx, *phoneChallenge)
		if err != nil {
			slog.ErrorContext(ctx, "failed to consume second registration challenge", "error", err)
		}
	}

	meta := input.Meta
	if meta.IPAddress == "" && primaryChallenge.IPAddress != nil {
		meta.IPAddress = *primaryChallenge.IPAddress
	}

	a.logSecurityEvent(
		&userID,
		domain.SecurityEventTypeRegistrationCompleted,
		meta,
		map[string]any{"flow_id": flow.ID},
	)

	if userEmail != nil && userEmail.VerifiedAt != nil {
		a.logSecurityEvent(
			&userID,
			domain.SecurityEventTypeEmailVerified,
			meta,
			map[string]any{"email": userEmail.Email},
		)
	}

	return &CompleteRegistrationOutput{User: &user}, nil
}

// verifyRegistrationChallenge finds the pending challenge for identifier that
// belongs to the given registration flow, validates the supplied code, and
// consumes it in memory. Invalid codes increment the attempt counter
// persistently. Consumption is persisted by the caller's CompleteRegistration
// transaction.
func (a *Application) verifyRegistrationChallenge(
	ctx context.Context,
	now time.Time,
	flowID int64,
	identifier string,
	purpose domain.VerificationPurpose,
	code string,
) (*domain.VerificationChallenge, error) {
	pendings, err := a.repo.ListPendingChallengesByIdentifier(ctx, identifier, purpose)
	if err != nil {
		slog.ErrorContext(ctx, "failed to list verification challenges", "error", err)

		return nil, goerror.NewServer(err)
	}

	var challenge *domain.VerificationChallenge

	for i := range pendings {
		if pendings[i].FlowID != nil && *pendings[i].FlowID == flowID {
			tmp := pendings[i]
			challenge = &tmp

			break
		}
	}

	if challenge == nil {
		return nil, goerror.NewBusiness("verification not found", goerror.CodeNotFound)
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

	if !a.sha256.Verify(string(challenge.CodeHash), code) {
		challenge.IncrementAttempts()

		uErr := a.repo.UpdateVerificationChallenge(ctx, *challenge)
		if uErr != nil {
			slog.ErrorContext(ctx, "failed to update verification challenge attempts", "error", uErr)

			return nil, goerror.NewServer(uErr)
		}

		slog.WarnContext(ctx, "invalid verification code")

		return nil, goerror.NewBusiness("invalid verification code", goerror.CodeUnauthorized)
	}

	if err := challenge.Consume(now); err != nil {
		return nil, goerror.NewBusiness(err.Error(), goerror.CodeInvalidInput)
	}

	return challenge, nil
}
