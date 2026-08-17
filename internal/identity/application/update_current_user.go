package application

import (
	"context"
	"strings"

	"github.com/qarven/oryon-go/internal/identity/domain"
	"github.com/qarven/oryon-go/internal/pkg/goerror"
	"github.com/qarven/oryon-go/internal/pkg/jwt"
)

type UpdateCurrentUserInput struct {
	Name       *string `validate:"omitempty,min=1"`
	AvatarURL  *string `validate:"omitempty,url"`
	UpdateMask []string
}

type UpdateCurrentUserOutput struct {
	User domain.User
}

func (a *Application) UpdateCurrentUser(ctx context.Context, input UpdateCurrentUserInput) (*UpdateCurrentUserOutput, error) {
	ctx, span := a.ins.Tracer("identity.application").Start(ctx, "UpdateCurrentUser")
	defer span.End()

	claims := jwt.GetAuth(ctx)
	if claims == nil {
		return nil, goerror.NewBusiness("unauthenticated", goerror.CodeUnauthorized)
	}

	user, err := a.repo.GetUserByID(ctx, claims.UserID)
	if err != nil {
		return nil, goerror.NewServer(err)
	}

	if user.IsDeleted() {
		return nil, goerror.NewBusiness("user is deleted", goerror.CodeNotFound)
	}

	now := a.clock.Now()

	// Apply field mask logic: if mask empty, update provided non-nil fields
	hasMask := len(input.UpdateMask) > 0
	maskMap := map[string]bool{}
	for _, m := range input.UpdateMask {
		maskMap[strings.ToLower(m)] = true
	}

	var nameToUpdate *string
	var avatarToUpdate *string
	shouldUpdateName := (input.Name != nil && (!hasMask || maskMap["name"]))
	shouldUpdateAvatar := (input.AvatarURL != nil && (!hasMask || maskMap["avatar_url"]))

	if shouldUpdateName {
		nameToUpdate = input.Name
	}

	if shouldUpdateAvatar {
		avatarToUpdate = input.AvatarURL
	}

	// If mask specifies field but input is nil, set to empty handling?
	// For name, if mask includes name but input.Name nil, we skip (no change)
	// For avatar_url, if mask includes avatar_url and input is nil, we interpret as clear? But spec says avatar_url optional string; if mask includes and value empty, clear
	if hasMask && maskMap["avatar_url"] && input.AvatarURL == nil {
		empty := ""
		avatarToUpdate = &empty // will be converted to nil in domain
	}

	if nameToUpdate == nil && avatarToUpdate == nil {
		return &UpdateCurrentUserOutput{User: user}, nil
	}

	if err := user.UpdateProfile(nameToUpdate, avatarToUpdate, now); err != nil {
		return nil, goerror.NewInvalidInput(err)
	}

	if err := a.repo.UpdateUser(ctx, user); err != nil {
		return nil, goerror.NewServer(err)
	}

	a.logSecurityEvent(ctx, &user.ID, "user.profile_updated", nil, nil, map[string]any{"fields": input.UpdateMask})

	return &UpdateCurrentUserOutput{User: user}, nil
}
