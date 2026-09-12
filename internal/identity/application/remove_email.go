package application

// import (
// 	"context"
// 	"errors"

// 	"github.com/jackc/pgx/v5/pgtype"
// 	"github.com/qarven/oryon-go/internal/identity/domain"
// 	"github.com/qarven/oryon-go/internal/pkg/goerror"
// 	"github.com/qarven/oryon-go/internal/pkg/jwt"
// )

// type RemoveEmailInput struct {
// 	EmailID int64 `validate:"required,gt=0"`
// }

// type RemoveEmailOutput struct{}

// func (a *Application) RemoveEmail(ctx context.Context, input RemoveEmailInput) (*RemoveEmailOutput, error) {
// 	ctx, span := a.ins.Tracer("identity.application").Start(ctx, "RemoveEmail")
// 	defer span.End()

// 	if err := a.validator.Validate(input); err != nil {
// 		return nil, goerror.NewInvalidInput(err)
// 	}

// 	claims := jwt.GetAuth(ctx)
// 	if claims == nil {
// 		return nil, goerror.NewBusiness("unauthenticated", goerror.CodeUnauthorized)
// 	}

// 	email, err := a.repo.GetUserEmailByID(ctx, input.EmailID)
// 	if err != nil {
// 		if errors.Is(err, domain.ErrEmailNotFound) {
// 			return nil, goerror.NewBusiness("email not found", goerror.CodeNotFound)
// 		}

// 		return nil, goerror.NewServer(err)
// 	}

// 	if email.UserID != claims.UserID {
// 		return nil, goerror.NewBusiness("email does not belong to user", goerror.CodeForbidden)
// 	}

// 	if email.IsDeleted() {
// 		return nil, goerror.NewBusiness("email already deleted", goerror.CodeInvalidInput)
// 	}

// 	if email.IsPrimary {
// 		return nil, goerror.NewBusiness("cannot remove primary email", goerror.CodeInvalidInput)
// 	}

// 	count, err := a.repo.CountUserEmails(ctx, claims.UserID)
// 	if err != nil {
// 		return nil, goerror.NewServer(err)
// 	}

// 	if count <= 1 {
// 		return nil, goerror.NewBusiness("cannot remove last email", goerror.CodeInvalidInput)
// 	}

// 	now := a.clock.Now()
// 	email.SoftDelete(now)
// 	// Use UpdateUserEmail with deleted_at
// 	if err := a.repo.UpdateUserEmail(ctx, email); err != nil {
// 		// fallback via SoftDeleteUserEmail if Update fails
// 		_ = a.repo.UpdateUserEmail
// 		return nil, goerror.NewServer(err)
// 	}

// 	// alternative: ensure deleted_at set via direct SQL
// 	_ = pgtype.Timestamptz{}

// 	a.logSecurityEvent(ctx, &claims.UserID, "email.removed", nil, map[string]any{"email": email.Email})

// 	return &RemoveEmailOutput{}, nil
// }
