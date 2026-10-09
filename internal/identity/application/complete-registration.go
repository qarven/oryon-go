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
	FlowID    domain.ID `validate:"required"`
	EmailCode *string   `validate:"required_without=PhoneCode"`
	PhoneCode *string   `validate:"required_without=EmailCode"`
	Meta      MetaInput `validate:"required"`
}

type CompleteRegistrationOutput struct {
	User *domain.User
}

type CompleteRegistrationData struct {
	User      domain.User
	UserEmail *domain.UserEmail
	UserPhone *domain.UserPhoneNumber
	PassCred  domain.PasswordCredential
	Flow      domain.AuthFlow
	Challenge domain.VerificationChallenge
}

type registrationFinalizeData struct {
	Data           CompleteRegistrationData
	User           domain.User
	FlowID         domain.ID
	Meta           MetaInput
	EmailChallenge *domain.VerificationChallenge
	PhoneChallenge *domain.VerificationChallenge
}

func (a *Application) CompleteRegistration(
	ctx context.Context,
	input CompleteRegistrationInput,
) (*CompleteRegistrationOutput, error) {
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

	err := a.validator.Validate(input)
	if err != nil {
		return nil, goerror.NewInvalidInput(err)
	}

	flow, err := a.repo.GetAuthFlowByID(ctx, input.FlowID)
	if errors.Is(err, domain.ErrAuthFlowNotFound) {
		slog.WarnContext(ctx, "registration flow not found")

		return nil, goerror.NewBusiness("registration flow not found", goerror.CodeNotFound)
	}

	if err != nil {
		slog.ErrorContext(ctx, "failed to get auth flow", "error", err)

		return nil, goerror.NewServer(err)
	}

	now := a.clock.Now()

	if flow.FlowType != domain.AuthFlowTypeRegistration {
		slog.WarnContext(ctx, "flow is not for registration",
			"flow_id", flow.ID,
			"flow_type", flow.FlowType,
		)

		return nil, goerror.NewBusiness("flow is not for registration", goerror.CodeInvalidInput)
	}

	if flow.IsExpired(now) {
		slog.WarnContext(ctx, "registration flow expired")

		return nil, goerror.NewBusiness("registration expired, please register again", goerror.CodeInvalidInput)
	}

	if flow.CompletedAt != nil || flow.FlowState.IsTerminal() {
		slog.WarnContext(ctx, "registration already completed")

		return nil, goerror.NewBusiness("registration already completed", goerror.CodeInvalidInput)
	}

	pending, err := a.pendingRegistrationFromFlow(flow)
	if err != nil {
		slog.WarnContext(ctx, "invalid registration flow data", "flow_id", flow.ID, "error", err)

		return nil, goerror.NewInvalidInput(nil, "flow", err.Error())
	}

	emailCha, phoneCha, err := a.verifyRegistrationChallenges(ctx, now, flow.ID, pending, emailCode, phoneCode)
	if err != nil {
		return nil, err
	}

	err = a.ensureRegistrationIdentifiersFree(ctx, pending)
	if err != nil {
		return nil, err
	}

	data, user := a.assembleRegistrationData(flow, pending, emailCha, phoneCha, now)

	err = a.finalizeRegistration(ctx, registrationFinalizeData{
		Data:           data,
		User:           user,
		FlowID:         flow.ID,
		Meta:           input.Meta,
		EmailChallenge: emailCha,
		PhoneChallenge: phoneCha,
	})
	if err != nil {
		return nil, err
	}

	return &CompleteRegistrationOutput{User: &user}, nil
}

func (a *Application) verifyRegistrationChallenge(
	ctx context.Context,
	now time.Time,
	flowID domain.ID,
	identifier string,
	purpose domain.VerificationPurpose,
	code string,
) (*domain.VerificationChallenge, error) {
	pendings, err := a.repo.ListPendingChallengesByIdentifier(ctx, identifier, purpose)
	if err != nil {
		slog.ErrorContext(ctx, "failed to list verification challenges",
			"flow_id", flowID,
			"purpose", purpose,
			"error", err,
		)

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
		slog.WarnContext(ctx, "verification challenge not found",
			"flow_id", flowID,
			"purpose", purpose,
		)

		return nil, goerror.NewBusiness("verification not found", goerror.CodeNotFound)
	}

	err = challenge.CanAttempt(now)
	if err != nil {
		slog.WarnContext(ctx, "verification challenge cannot be attempted",
			"flow_id", flowID,
			"challenge_id", challenge.ID,
			"error", err,
		)

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

	challenge.ConsumedAt = &now

	if !a.sha256.Verify(string(challenge.CodeHash), code) {
		challenge.Attempts++

		err := a.repo.UpdateVerificationChallenge(ctx, *challenge)
		if err != nil {
			slog.ErrorContext(ctx, "failed to update verification challenge attempts",
				"challenge_id", challenge.ID,
				"error", err,
			)

			return nil, goerror.NewServer(err)
		}

		slog.WarnContext(ctx, "invalid verification code", "challenge_id", challenge.ID)

		return nil, goerror.NewBusiness("invalid verification code", goerror.CodeUnauthorized)
	}

	return challenge, nil
}

func (a *Application) verifyRegistrationChallenges(
	ctx context.Context,
	now time.Time,
	flowID domain.ID,
	pending pendingRegistration,
	emailCode, phoneCode string,
) (*domain.VerificationChallenge, *domain.VerificationChallenge, error) {
	var emailChallenge, phoneChallenge *domain.VerificationChallenge

	if emailCode != "" {
		challenge, err := a.verifyRegistrationChallenge(
			ctx,
			now,
			flowID,
			pending.Email,
			domain.VerificationPurposeEmailVerification,
			emailCode,
		)
		if err != nil {
			return nil, nil, err
		}

		emailChallenge = challenge
	}

	if phoneCode != "" {
		challenge, err := a.verifyRegistrationChallenge(
			ctx,
			now,
			flowID,
			pending.Phone,
			domain.VerificationPurposePhoneVerification,
			phoneCode,
		)
		if err != nil {
			return nil, nil, err
		}

		phoneChallenge = challenge
	}

	return emailChallenge, phoneChallenge, nil
}

func (a *Application) ensureRegistrationIdentifiersFree(
	ctx context.Context,
	pending pendingRegistration,
) error {
	if pending.Email != "" {
		_, err := a.repo.GetUserEmailByEmail(ctx, pending.Email)
		if err == nil {
			slog.WarnContext(ctx, "email already registered")

			return goerror.NewBusiness("email already registered", goerror.CodeConflict)
		}

		if !errors.Is(err, domain.ErrEmailNotFound) {
			slog.ErrorContext(ctx, "failed to get user email by email", "error", err)

			return goerror.NewServer(err)
		}
	}

	if pending.Phone != "" {
		_, err := a.repo.GetUserPhoneByPhone(ctx, pending.Phone)
		if err == nil {
			slog.WarnContext(ctx, "phone already registered")

			return goerror.NewBusiness("phone already registered", goerror.CodeConflict)
		}

		if !errors.Is(err, domain.ErrPhoneNotFound) {
			slog.ErrorContext(ctx, "failed to get user phone by phone number", "error", err)

			return goerror.NewServer(err)
		}
	}

	return nil
}

func (a *Application) buildRegistrationContacts(
	userID domain.ID,
	pending pendingRegistration,
	emailChallenge, phoneChallenge *domain.VerificationChallenge,
	now time.Time,
) (*domain.UserEmail, *domain.UserPhoneNumber) {
	var userEmail *domain.UserEmail
	if pending.Email != "" {
		userEmail = &domain.UserEmail{
			ID:        domain.IDFrom(a.uuid.Generate()),
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
			ID:        domain.IDFrom(a.uuid.Generate()),
			UserID:    userID,
			Phone:     pending.Phone,
			CreatedAt: now,
		}

		if phoneChallenge != nil {
			userPhone.VerifiedAt = &now
		}
	}

	return userEmail, userPhone
}

func (a *Application) assembleRegistrationData(
	flow *domain.AuthFlow,
	pending pendingRegistration,
	emailChallenge, phoneChallenge *domain.VerificationChallenge,
	now time.Time,
) (CompleteRegistrationData, domain.User) {
	userID := domain.IDFrom(a.uuid.Generate())

	user := domain.User{
		ID:        userID,
		Status:    domain.UserStatusActive,
		Name:      pending.Name,
		CreatedAt: now,
		UpdatedAt: now,
	}

	userEmail, userPhone := a.buildRegistrationContacts(
		userID,
		pending,
		emailChallenge,
		phoneChallenge,
		now,
	)

	primaryChallenge := emailChallenge
	if primaryChallenge == nil {
		primaryChallenge = phoneChallenge
	}

	flow.FlowState = domain.AuthFlowStateCompleted
	flow.CompletedAt = &now

	return CompleteRegistrationData{
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
	}, user
}

func (a *Application) finalizeRegistration(
	ctx context.Context,
	finalize registrationFinalizeData,
) error {
	err := a.repo.CompleteRegistration(ctx, finalize.Data)
	if errors.Is(err, domain.ErrIdentifierConflict) {
		slog.WarnContext(ctx, "identifier taken during registration completion")

		return goerror.NewBusiness("identifier already registered", goerror.CodeConflict)
	}

	if err != nil {
		slog.ErrorContext(ctx, "failed to complete registration", "error", err)

		return goerror.NewServer(err)
	}

	// The persistence transaction consumes the primary challenge; when both
	// channels were verified, consume the second one as well. The user row
	// already exists at this point, so a failure here is cleanup only.
	if finalize.EmailChallenge != nil && finalize.PhoneChallenge != nil {
		err := a.repo.UpdateVerificationChallenge(ctx, *finalize.PhoneChallenge)
		if err != nil {
			slog.ErrorContext(ctx, "failed to consume second registration challenge",
				"challenge_id", finalize.PhoneChallenge.ID,
				"error", err,
			)
		}
	}

	meta := finalize.Meta
	if meta.IPAddress == "" && finalize.Data.Challenge.IPAddress != nil {
		meta.IPAddress = *finalize.Data.Challenge.IPAddress
	}

	a.securityEvent(domain.SecurityEventTypeRegistrationCompleted).
		ForUser(&finalize.User.ID).
		WithMeta(meta).
		With("flow_id", finalize.FlowID).
		Emit(ctx)

	if finalize.Data.UserEmail != nil && finalize.Data.UserEmail.VerifiedAt != nil {
		a.securityEvent(domain.SecurityEventTypeEmailVerified).
			ForUser(&finalize.User.ID).
			WithMeta(meta).
			With("email", finalize.Data.UserEmail.Email).
			Emit(ctx)
	}

	return nil
}
