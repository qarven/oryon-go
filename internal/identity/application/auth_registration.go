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

const (
	registrationRequestEmailKeyPrefix = "registration:req:email:"
	registrationRequestPhoneKeyPrefix = "registration:req:phone:"
	registrationRequestIPKeyPrefix    = "registration:req:ip:"
)

const (
	regCtxName         = "name"
	regCtxEmail        = "email"
	regCtxPhone        = "phone"
	regCtxPasswordHash = "password_hash"
)

type RegistrationInput struct {
	Email    *string   `validate:"omitempty,email"`
	Phone    *string   `validate:"omitempty,e164"`
	Password string    `validate:"required,password"`
	Name     string    `validate:"required,min=3"`
	Meta     MetaInput `validate:"required"`
}

type RegistrationOutput struct {
	Flow domain.AuthFlow
}

type CompleteRegistrationData struct {
	User      domain.User
	UserEmail *domain.UserEmail
	UserPhone *domain.UserPhoneNumber
	PassCred  domain.PasswordCredential
	Flow      domain.AuthFlow
	Challenge domain.VerificationChallenge
}

type EventRegistrationData struct {
	Name     string `json:"name"`
	Code     string `json:"code"`
	Identity string `json:"identity"`
	Channel  string `json:"channel"` // email, phone
}

func (a *Application) Registration(ctx context.Context, input RegistrationInput) (*RegistrationOutput, error) {
	ctx, span := a.ins.Tracer("identity.application").Start(ctx, "Registration")
	defer span.End()

	err := a.validator.Validate(input)
	if err != nil {
		return nil, goerror.NewInvalidInput(err)
	}

	email, phone := normalizeRegistrationContact(input)

	err = a.checkVerificationRateLimit(ctx, email, phone, strings.TrimSpace(input.Meta.IPAddress))
	if err != nil {
		return nil, err
	}

	err = a.ensureRegistrationContactsFree(ctx, email, phone)
	if err != nil {
		return nil, err
	}

	hash, err := a.hashRegistrationPassword(ctx, input.Password)
	if err != nil {
		return nil, err
	}

	flow, now := a.buildRegistrationFlow(registrationFlowData{
		flowID:   a.uid.Generate(),
		name:     strings.TrimSpace(input.Name),
		password: string(hash),
		email:    email,
		phone:    phone,
		meta:     input.Meta,
	})

	challenges, err := a.issueRegistrationChallenges(ctx, registrationChallengeData{
		flowID:      flow.ID,
		name:        strings.TrimSpace(input.Name),
		ipAddress:   input.Meta.IPAddress,
		now:         now,
		maxAttempts: int16(a.config.GetInt("modules.identity.verification.max_attempts")),
		ttl:         a.config.GetMinute("modules.identity.verification.ttl"),
	}, email, phone)
	if err != nil {
		return nil, err
	}

	err = a.storeRegistrationFlow(ctx, registrationStoreData{
		Flow:       flow,
		Challenges: challenges,
		Meta:       input.Meta,
		Email:      email,
		Phone:      phone,
	})
	if err != nil {
		return nil, err
	}

	return &RegistrationOutput{Flow: flow}, nil
}

type registrationStoreData struct {
	Flow       domain.AuthFlow
	Challenges []domain.VerificationChallenge
	Meta       MetaInput
	Email      string
	Phone      string
}

// storeRegistrationFlow persists the registration flow and emits the
// registration-requested security event.
func (a *Application) storeRegistrationFlow(
	ctx context.Context,
	data registrationStoreData,
) error {
	err := a.repo.CreateRegistrationFlow(ctx, data.Flow, data.Challenges)
	if err != nil {
		slog.ErrorContext(ctx, "failed to create registration flow", "error", err)

		return goerror.NewServer(err)
	}

	a.logSecurityEvent(
		ctx,
		nil,
		domain.SecurityEventTypeRegistrationRequested,
		data.Meta,
		map[string]any{securityEventFlowIDKey: data.Flow.ID, "email": data.Email, "phone": data.Phone},
	)

	return nil
}

type registrationFlowData struct {
	flowID   int64
	name     string
	password string
	email    string
	phone    string
	meta     MetaInput
}

// buildRegistrationFlow assembles the pending-verification auth flow and
// returns it with its creation time.
func (a *Application) buildRegistrationFlow(data registrationFlowData) (domain.AuthFlow, time.Time) {
	now := a.clock.Now()

	return domain.AuthFlow{
		ID:        data.flowID,
		UserID:    nil,
		FlowType:  domain.AuthFlowTypeRegistration,
		FlowState: domain.AuthFlowStatePendingVerification,
		IPAddress: &data.meta.IPAddress,
		UserAgent: &data.meta.UserAgent,
		Context:   registrationFlowContext(data.name, data.password, data.email, data.phone),
		ExpiresAt: now.Add(a.config.GetMinute("modules.identity.flow.ttl")),
		CreatedAt: now,
	}, now
}

// hashRegistrationPassword hashes the registration password.
func (a *Application) hashRegistrationPassword(ctx context.Context, password string) ([]byte, error) {
	hash, err := a.argon2id.Hash(password)
	if err != nil {
		slog.ErrorContext(ctx, "failed to hash password", "error", err)

		return nil, goerror.NewServer(err)
	}

	return hash, nil
}

// normalizeRegistrationContact trims the optional email/phone identifiers.
func normalizeRegistrationContact(input RegistrationInput) (string, string) {
	var email, phone string
	if input.Email != nil {
		email = strings.ToLower(strings.TrimSpace(*input.Email))
	}

	if input.Phone != nil {
		phone = strings.TrimSpace(*input.Phone)
	}

	return email, phone
}

// ensureRegistrationContactsFree rejects already-registered identifiers.
func (a *Application) ensureRegistrationContactsFree(
	ctx context.Context,
	email, phone string,
) error {
	if email != "" {
		_, err := a.repo.GetUserEmailByEmail(ctx, email)
		if err == nil {
			slog.WarnContext(ctx, "email already exists")

			return goerror.NewBusiness("email already registered", goerror.CodeConflict)
		}

		if !errors.Is(err, domain.ErrEmailNotFound) {
			slog.ErrorContext(ctx, "failed to get user email by email", "error", err)

			return goerror.NewServer(err)
		}
	}

	if phone != "" {
		_, err := a.repo.GetUserPhoneByPhone(ctx, phone)
		if err == nil {
			slog.WarnContext(ctx, "phone already exists")

			return goerror.NewBusiness("phone already registered", goerror.CodeConflict)
		}

		if !errors.Is(err, domain.ErrPhoneNotFound) {
			slog.ErrorContext(ctx, "failed to get user phone by phone number", "error", err)

			return goerror.NewServer(err)
		}
	}

	return nil
}

// registrationFlowContext builds the registration flow context payload.
func registrationFlowContext(name, passwordHash, email, phone string) map[string]any {
	flowCtx := map[string]any{
		regCtxName:         name,
		regCtxPasswordHash: passwordHash,
	}
	if email != "" {
		flowCtx[regCtxEmail] = email
	}

	if phone != "" {
		flowCtx[regCtxPhone] = phone
	}

	return flowCtx
}

type registrationChallengeData struct {
	flowID      int64
	name        string
	ipAddress   string
	now         time.Time
	maxAttempts int16
	ttl         time.Duration
}

// issueRegistrationChallenges creates a verification challenge per
// non-empty identifier and publishes its delivery event.
func (a *Application) issueRegistrationChallenges(
	ctx context.Context,
	data registrationChallengeData,
	email, phone string,
) ([]domain.VerificationChallenge, error) {
	var challenges []domain.VerificationChallenge

	if email != "" {
		challenge, err := a.issueRegistrationChallenge(
			ctx,
			data,
			email,
			"email",
			domain.VerificationPurposeEmailVerification,
		)
		if err != nil {
			slog.ErrorContext(ctx, "failed to create email verification code", "error", err)

			return nil, goerror.NewServer(err)
		}

		challenges = append(challenges, *challenge)
	}

	if phone != "" {
		challenge, err := a.issueRegistrationChallenge(
			ctx,
			data,
			phone,
			"phone",
			domain.VerificationPurposePhoneVerification,
		)
		if err != nil {
			slog.ErrorContext(ctx, "failed to create phone verification code", "error", err)

			return nil, goerror.NewServer(err)
		}

		challenges = append(challenges, *challenge)
	}

	return challenges, nil
}

// issueRegistrationChallenge creates a single verification challenge and
// publishes its delivery event.
func (a *Application) issueRegistrationChallenge(
	ctx context.Context,
	data registrationChallengeData,
	identifier, channel string,
	purpose domain.VerificationPurpose,
) (*domain.VerificationChallenge, error) {
	rawCode, err := generate6DigitCode()
	if err != nil {
		return nil, err
	}

	codeHash, err := a.sha256.Hash(rawCode)
	if err != nil {
		return nil, err
	}

	challenge := domain.VerificationChallenge{
		ID:          a.uid.Generate(),
		UserID:      nil,
		FlowID:      &data.flowID,
		Identifier:  identifier,
		Purpose:     purpose,
		CodeHash:    codeHash,
		Attempts:    0,
		MaxAttempts: data.maxAttempts,
		IPAddress:   &data.ipAddress,
		ExpiresAt:   data.now.Add(data.ttl),
		CreatedAt:   data.now,
	}

	err = a.event.PublishEventRegistration(ctx, EventRegistrationData{
		Name:     data.name,
		Channel:  channel,
		Identity: identifier,
		Code:     rawCode,
	})

	return &challenge, err
}

// ===== Registration: complete =====

type CompleteRegistrationInput struct {
	FlowID    int64     `validate:"required"`
	EmailCode *string   `validate:"required_without=PhoneCode"`
	PhoneCode *string   `validate:"required_without=EmailCode"`
	Meta      MetaInput `validate:"required"`
}

type CompleteRegistrationOutput struct {
	User *domain.User
}

func (a *Application) CompleteRegistration(
	ctx context.Context,
	input CompleteRegistrationInput,
) (*CompleteRegistrationOutput, error) {
	ctx, span := a.ins.Tracer("identity.application").Start(ctx, "CompleteRegistration")
	defer span.End()

	emailCode, phoneCode := parseRegistrationCodes(&input)

	validateErr := a.validator.Validate(input)
	if validateErr != nil {
		return nil, goerror.NewInvalidInput(validateErr)
	}

	flow, pending, now, err := a.loadRegistrationFlow(ctx, input.FlowID)
	if err != nil {
		return nil, err
	}

	emailChallenge, phoneChallenge, err := a.verifyRegistrationChallenges(
		ctx,
		now,
		flow.ID,
		pending,
		emailCode,
		phoneCode,
	)
	if err != nil {
		return nil, err
	}

	err = a.ensureRegistrationIdentifiersFree(ctx, pending)
	if err != nil {
		return nil, err
	}

	data, user := a.assembleRegistrationData(flow, pending, emailChallenge, phoneChallenge, now)

	err = a.finalizeRegistration(ctx, registrationFinalizeData{
		Data:           data,
		User:           user,
		FlowID:         flow.ID,
		Meta:           input.Meta,
		EmailChallenge: emailChallenge,
		PhoneChallenge: phoneChallenge,
	})
	if err != nil {
		return nil, err
	}

	return &CompleteRegistrationOutput{User: &user}, nil
}

type registrationFinalizeData struct {
	Data           CompleteRegistrationData
	User           domain.User
	FlowID         int64
	Meta           MetaInput
	EmailChallenge *domain.VerificationChallenge
	PhoneChallenge *domain.VerificationChallenge
}

// finalizeRegistration persists the registration, consumes a second verified
// challenge when both channels were verified, and emits security events.
func (a *Application) finalizeRegistration(
	ctx context.Context,
	finalize registrationFinalizeData,
) error {
	err := a.repo.CompleteRegistration(ctx, finalize.Data)
	if err != nil {
		if errors.Is(err, domain.ErrIdentifierConflict) {
			slog.WarnContext(ctx, "identifier taken during registration completion")

			return goerror.NewBusiness("identifier already registered", goerror.CodeConflict)
		}

		slog.ErrorContext(ctx, "failed to complete registration", "error", err)

		return goerror.NewServer(err)
	}

	// The persistence transaction consumes the primary challenge; when both
	// channels were verified, consume the second one as well. The user row
	// already exists at this point, so a failure here is cleanup only.
	if finalize.EmailChallenge != nil && finalize.PhoneChallenge != nil {
		err := a.repo.UpdateVerificationChallenge(ctx, *finalize.PhoneChallenge)
		if err != nil {
			slog.ErrorContext(ctx, "failed to consume second registration challenge", "error", err)
		}
	}

	meta := finalize.Meta
	if meta.IPAddress == "" && finalize.Data.Challenge.IPAddress != nil {
		meta.IPAddress = *finalize.Data.Challenge.IPAddress
	}

	a.logSecurityEvent(
		ctx,
		&finalize.User.ID,
		domain.SecurityEventTypeRegistrationCompleted,
		meta,
		map[string]any{securityEventFlowIDKey: finalize.FlowID},
	)

	if finalize.Data.UserEmail != nil && finalize.Data.UserEmail.VerifiedAt != nil {
		a.logSecurityEvent(
			ctx,
			&finalize.User.ID,
			domain.SecurityEventTypeEmailVerified,
			meta,
			map[string]any{"email": finalize.Data.UserEmail.Email},
		)
	}

	return nil
}

// parseRegistrationCodes trims the supplied codes in place and returns them.
func parseRegistrationCodes(input *CompleteRegistrationInput) (string, string) {
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

	return emailCode, phoneCode
}

// loadRegistrationFlow returns the registration flow and its pending data,
// rejecting flows that are missing, foreign, expired, or already completed.
func (a *Application) loadRegistrationFlow(
	ctx context.Context,
	flowID int64,
) (*domain.AuthFlow, pendingRegistration, time.Time, error) {
	flow, err := a.repo.GetAuthFlowByID(ctx, flowID)
	if errors.Is(err, domain.ErrAuthFlowNotFound) {
		return nil, pendingRegistration{}, time.Time{}, goerror.NewBusiness(
			"registration flow not found",
			goerror.CodeNotFound,
		)
	}

	if err != nil {
		slog.ErrorContext(ctx, "failed to get auth flow", "error", err)

		return nil, pendingRegistration{}, time.Time{}, goerror.NewServer(err)
	}

	now := a.clock.Now()

	if flow.FlowType != domain.AuthFlowTypeRegistration {
		return nil, pendingRegistration{}, time.Time{}, goerror.NewBusiness(
			"flow is not for registration",
			goerror.CodeInvalidInput,
		)
	}

	if flow.IsExpired(now) {
		return nil, pendingRegistration{}, time.Time{}, goerror.NewBusiness(
			"registration expired, please register again",
			goerror.CodeInvalidInput,
		)
	}

	if flow.CompletedAt != nil || flow.FlowState.IsTerminal() {
		return nil, pendingRegistration{}, time.Time{}, goerror.NewBusiness(
			"registration already completed",
			goerror.CodeInvalidInput,
		)
	}

	pending, err := pendingRegistrationFromFlow(flow)
	if err != nil {
		return nil, pendingRegistration{}, time.Time{}, goerror.NewInvalidInput(nil, "flow", err.Error())
	}

	return flow, pending, now, nil
}

// verifyRegistrationChallenges validates the supplied codes against their
// pending challenges.
func (a *Application) verifyRegistrationChallenges(
	ctx context.Context,
	now time.Time,
	flowID int64,
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

// ensureRegistrationIdentifiersFree pre-checks uniqueness so a lost race
// surfaces as 409 instead of 500. The persistence layer re-checks inside
// the transaction.
func (a *Application) ensureRegistrationIdentifiersFree(
	ctx context.Context,
	pending pendingRegistration,
) error {
	if pending.Email != "" {
		_, err := a.repo.GetUserEmailByEmail(ctx, pending.Email)
		if err == nil {
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
			return goerror.NewBusiness("phone already registered", goerror.CodeConflict)
		}

		if !errors.Is(err, domain.ErrPhoneNotFound) {
			slog.ErrorContext(ctx, "failed to get user phone by phone number", "error", err)

			return goerror.NewServer(err)
		}
	}

	return nil
}

// assembleRegistrationData materializes the domain rows for a verified
// registration and marks the flow completed.
func (a *Application) assembleRegistrationData(
	flow *domain.AuthFlow,
	pending pendingRegistration,
	emailChallenge, phoneChallenge *domain.VerificationChallenge,
	now time.Time,
) (CompleteRegistrationData, domain.User) {
	userID := a.uid.Generate()

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

// buildRegistrationContacts materializes the email/phone rows for a verified
// registration, marking them verified when their challenge was verified.
func (a *Application) buildRegistrationContacts(
	userID int64,
	pending pendingRegistration,
	emailChallenge, phoneChallenge *domain.VerificationChallenge,
	now time.Time,
) (*domain.UserEmail, *domain.UserPhoneNumber) {
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

	return userEmail, userPhone
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

	err = challenge.CanAttempt(now)
	if err != nil {
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
		return nil, a.rejectChallengeCodeMismatch(ctx, challenge)
	}

	err = challenge.Consume(now)
	if err != nil {
		return nil, goerror.NewBusiness(err.Error(), goerror.CodeInvalidInput)
	}

	return challenge, nil
}

// rejectChallengeCodeMismatch records a failed code attempt persistently
// and reports the code as invalid.
func (a *Application) rejectChallengeCodeMismatch(
	ctx context.Context,
	challenge *domain.VerificationChallenge,
) error {
	challenge.IncrementAttempts()

	updateErr := a.repo.UpdateVerificationChallenge(ctx, *challenge)
	if updateErr != nil {
		slog.ErrorContext(ctx, "failed to update verification challenge attempts", "error", updateErr)

		return goerror.NewServer(updateErr)
	}

	slog.WarnContext(ctx, "invalid verification code")

	return goerror.NewBusiness("invalid verification code", goerror.CodeUnauthorized)
}

type pendingRegistration struct {
	Name         string
	Email        string
	Phone        string
	PasswordHash string
}

// ErrRegistrationDataMissing is returned when a registration flow carries
// no usable registration data.
var ErrRegistrationDataMissing = errors.New("registration data missing")

func pendingRegistrationFromFlow(flow *domain.AuthFlow) (pendingRegistration, error) {
	if flow.Context == nil {
		return pendingRegistration{}, ErrRegistrationDataMissing
	}

	get := func(key string) string {
		value, ok := flow.Context[key].(string)
		if !ok {
			return ""
		}

		return strings.TrimSpace(value)
	}

	out := pendingRegistration{
		Name:         get(regCtxName),
		Email:        strings.ToLower(get(regCtxEmail)),
		Phone:        get(regCtxPhone),
		PasswordHash: get(regCtxPasswordHash),
	}

	if out.Name == "" || out.PasswordHash == "" {
		return pendingRegistration{}, ErrRegistrationDataMissing
	}

	if out.Email == "" && out.Phone == "" {
		return pendingRegistration{}, ErrRegistrationDataMissing
	}

	return out, nil
}

// ===== Registration: resend code =====

const (
	resendChannelEmail = "email"
	resendChannelPhone = "phone"
)

type ResendRegistrationCodeInput struct {
	FlowID int64     `validate:"required"`
	Meta   MetaInput `validate:"required"`
}

type ResendRegistrationCodeOutput struct {
	Flow domain.AuthFlow
}

type resendTarget struct {
	identifier string
	channel    string
	purpose    domain.VerificationPurpose
}

func (a *Application) ResendRegistrationCode(
	ctx context.Context,
	input ResendRegistrationCodeInput,
) (*ResendRegistrationCodeOutput, error) {
	ctx, span := a.ins.Tracer("identity.application").Start(ctx, "ResendRegistrationCode")
	defer span.End()

	validateErr := a.validator.Validate(input)
	if validateErr != nil {
		return nil, goerror.NewInvalidInput(validateErr)
	}

	flow, pending, err := a.loadResendableFlow(ctx, input.FlowID)
	if err != nil {
		return nil, err
	}

	err = a.checkVerificationRateLimit(ctx, pending.Email, pending.Phone, input.Meta.IPAddress)
	if err != nil {
		return nil, err
	}

	targets := resendTargets(pending.Email, pending.Phone)

	challenges, rawCodes, err := a.issueResendChallenges(
		ctx,
		targets,
		flow.ID,
		input.Meta.IPAddress,
		a.clock.Now(),
	)
	if err != nil {
		return nil, err
	}

	err = a.repo.ResendRegistrationCode(ctx, challenges)
	if err != nil {
		slog.ErrorContext(ctx, "failed to resend registration code", "error", err)

		return nil, goerror.NewServer(err)
	}

	err = a.publishResendEvents(ctx, pending.Name, targets, rawCodes)
	if err != nil {
		return nil, err
	}

	a.logSecurityEvent(
		ctx,
		nil,
		domain.SecurityEventTypeRegistrationRequested,
		input.Meta,
		map[string]any{
			securityEventFlowIDKey: flow.ID,
			regCtxEmail:            pending.Email,
			regCtxPhone:            pending.Phone,
			"resend":               true,
		},
	)

	return &ResendRegistrationCodeOutput{Flow: *flow}, nil
}

// loadResendableFlow returns the registration flow and its pending data,
// rejecting flows that are missing, foreign, expired, or already completed.
func (a *Application) loadResendableFlow(
	ctx context.Context,
	flowID int64,
) (*domain.AuthFlow, pendingRegistration, error) {
	flow, err := a.repo.GetAuthFlowByID(ctx, flowID)
	if errors.Is(err, domain.ErrAuthFlowNotFound) {
		return nil, pendingRegistration{}, goerror.NewBusiness("registration flow not found", goerror.CodeNotFound)
	}

	if err != nil {
		slog.ErrorContext(ctx, "failed to get auth flow", "error", err)

		return nil, pendingRegistration{}, goerror.NewServer(err)
	}

	if flow.FlowType != domain.AuthFlowTypeRegistration {
		return nil, pendingRegistration{}, goerror.NewBusiness("flow is not for registration", goerror.CodeInvalidInput)
	}

	if flow.IsExpired(a.clock.Now()) {
		return nil, pendingRegistration{}, goerror.NewBusiness(
			"registration expired, please register again",
			goerror.CodeInvalidInput,
		)
	}

	if flow.CompletedAt != nil || flow.FlowState.IsTerminal() {
		return nil, pendingRegistration{}, goerror.NewBusiness("registration already completed", goerror.CodeInvalidInput)
	}

	pending, err := pendingRegistrationFromFlow(flow)
	if err != nil {
		return nil, pendingRegistration{}, goerror.NewInvalidInput(nil, "flow", err.Error())
	}

	return flow, pending, nil
}

func resendTargets(email, phone string) []resendTarget {
	targets := []resendTarget{}

	if email != "" {
		targets = append(targets, resendTarget{
			identifier: email,
			channel:    resendChannelEmail,
			purpose:    domain.VerificationPurposeEmailVerification,
		})
	}

	if phone != "" {
		targets = append(targets, resendTarget{
			identifier: phone,
			channel:    resendChannelPhone,
			purpose:    domain.VerificationPurposePhoneVerification,
		})
	}

	return targets
}

// publishResendEvents emits the OTP delivery events for all resend targets.
func (a *Application) publishResendEvents(
	ctx context.Context,
	name string,
	targets []resendTarget,
	rawCodes []string,
) error {
	for i, target := range targets {
		err := a.publishResendEvent(ctx, name, target, rawCodes[i])
		if err != nil {
			return err
		}
	}

	return nil
}

// publishResendEvent emits the OTP delivery event for a single resend target.
func (a *Application) publishResendEvent(ctx context.Context, name string, target resendTarget, code string) error {
	err := a.event.PublishEventRegistration(ctx, EventRegistrationData{
		Name:     name,
		Channel:  target.channel,
		Identity: target.identifier,
		Code:     code,
	})
	if err != nil {
		slog.ErrorContext(ctx, "failed to publish resend registration event", "error", err)

		return goerror.NewServer(err)
	}

	return nil
}

// issueResendChallenges issues a fresh OTP challenge per target and returns
// them alongside the plaintext codes for event publishing. The codes are
// only returned to the caller, never persisted.
func (a *Application) issueResendChallenges(
	ctx context.Context,
	targets []resendTarget,
	flowID int64,
	ipAddress string,
	now time.Time,
) ([]domain.VerificationChallenge, []string, error) {
	return a.newResendChallenges(
		ctx,
		targets,
		flowID,
		ipAddress,
		now,
		int16(a.config.GetInt("modules.identity.verification.max_attempts")),
		a.config.GetMinute("modules.identity.verification.ttl"),
	)
}

// newResendChallenges issues a fresh OTP challenge per target and returns them
// alongside the plaintext codes for event publishing. The codes are only
// returned to the caller, never persisted.
func (a *Application) newResendChallenges(
	ctx context.Context,
	targets []resendTarget,
	flowID int64,
	ipAddress string,
	now time.Time,
	maxAttempts int16,
	ttl time.Duration,
) ([]domain.VerificationChallenge, []string, error) {
	challenges := make([]domain.VerificationChallenge, 0, len(targets))
	rawCodes := make([]string, 0, len(targets))

	for _, target := range targets {
		rawCode, err := generate6DigitCode()
		if err != nil {
			slog.ErrorContext(ctx, "failed to generate verification code", "error", err)

			return nil, nil, goerror.NewServer(err)
		}

		codeHash, err := a.sha256.Hash(rawCode)
		if err != nil {
			slog.ErrorContext(ctx, "failed to hash verification code", "error", err)

			return nil, nil, goerror.NewServer(err)
		}

		challenges = append(challenges, domain.VerificationChallenge{
			ID:          a.uid.Generate(),
			UserID:      nil,
			FlowID:      &flowID,
			Identifier:  target.identifier,
			Purpose:     target.purpose,
			CodeHash:    codeHash,
			Attempts:    0,
			MaxAttempts: maxAttempts,
			IPAddress:   &ipAddress,
			ExpiresAt:   now.Add(ttl),
			CreatedAt:   now,
		})
		rawCodes = append(rawCodes, rawCode)
	}

	return challenges, rawCodes, nil
}
