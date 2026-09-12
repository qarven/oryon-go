package application

// import (
// 	"context"

// 	"github.com/qarven/oryon-go/internal/identity/domain"
// 	"github.com/qarven/oryon-go/internal/pkg/goerror"
// 	"github.com/qarven/oryon-go/internal/pkg/jwt"
// )

// type ListEmailsInput struct {
// 	PageSize       int32 `validate:"omitempty,gte=0,lte=100"`
// 	PageToken      string
// 	IncludeDeleted bool
// }

// type ListEmailsOutput struct {
// 	Emails        []domain.UserEmail
// 	NextPageToken string
// }

// func (a *Application) ListEmails(ctx context.Context, input ListEmailsInput) (*ListEmailsOutput, error) {
// 	ctx, span := a.ins.Tracer("identity.application").Start(ctx, "ListEmails")
// 	defer span.End()

// 	claims := jwt.GetAuth(ctx)
// 	if claims == nil {
// 		return nil, goerror.NewBusiness("unauthenticated", goerror.CodeUnauthorized)
// 	}

// 	emails, err := a.repo.ListUserEmailsByUserID(ctx, claims.UserID, input.IncludeDeleted)
// 	if err != nil {
// 		return nil, goerror.NewServer(err)
// 	}

// 	// Simple pagination
// 	limit := input.PageSize
// 	if limit <= 0 {
// 		limit = 10
// 	}

// 	if limit > 100 {
// 		limit = 100
// 	}

// 	offset := int32(0)
// 	if input.PageToken != "" {
// 		for _, ch := range input.PageToken {
// 			if ch < '0' || ch > '9' {
// 				offset = 0
// 				break
// 			}

// 			offset = offset*10 + int32(ch-'0')
// 		}
// 	}

// 	total := int32(len(emails))
// 	end := min(offset+limit, total)

// 	var paged []domain.UserEmail
// 	if offset < total {
// 		paged = emails[offset:end]
// 	}

// 	next := ""
// 	if end < total {
// 		next = itoa32(end)
// 	}

// 	return &ListEmailsOutput{
// 		Emails:        paged,
// 		NextPageToken: next,
// 	}, nil
// }
