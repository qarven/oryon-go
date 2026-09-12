package application

// type ListSessionsInput struct {
// 	PageSize       int32 `validate:"omitempty,gte=0,lte=100"`
// 	PageToken      string
// 	IncludeRevoked bool
// 	IncludeExpired bool
// }

// type ListSessionsOutput struct {
// 	Sessions      []domain.Session
// 	NextPageToken string
// 	TotalSize     int32
// }

// func (a *Application) ListSessions(ctx context.Context, input ListSessionsInput) (*ListSessionsOutput, error) {
// 	ctx, span := a.ins.Tracer("identity.application").Start(ctx, "ListSessions")
// 	defer span.End()

// 	claims := jwt.GetAuth(ctx)
// 	if claims == nil {
// 		return nil, goerror.NewBusiness("unauthenticated", goerror.CodeUnauthorized)
// 	}

// 	sessions, err := a.repo.ListSessionsByUserID(ctx, claims.UserID, input.IncludeRevoked, input.IncludeExpired)
// 	if err != nil {
// 		return nil, goerror.NewServer(err)
// 	}

// 	// Simple pagination via page_token as offset
// 	offset := int32(0)
// 	limit := input.PageSize
// 	if limit <= 0 {
// 		limit = 10
// 	}

// 	if limit > 100 {
// 		limit = 100
// 	}

// 	// page_token is offset string
// 	if input.PageToken != "" {
// 		// try parse int
// 		var v int32
// 		for _, ch := range input.PageToken {
// 			if ch < '0' || ch > '9' {
// 				v = 0
// 				break
// 			}

// 			v = v*10 + int32(ch-'0')
// 		}

// 		offset = v
// 	}

// 	total := int32(len(sessions))
// 	end := min(offset+limit, total)

// 	var paged []domain.Session
// 	if offset < total {
// 		paged = sessions[offset:end]
// 	}

// 	nextToken := ""
// 	if end < total {
// 		nextToken = itoa32(end)
// 	}

// 	return &ListSessionsOutput{
// 		Sessions:      paged,
// 		NextPageToken: nextToken,
// 		TotalSize:     total,
// 	}, nil
// }

// func itoa32(n int32) string {
// 	if n == 0 {
// 		return "0"
// 	}

// 	var buf [10]byte
// 	pos := len(buf)
// 	for n > 0 {
// 		pos--
// 		buf[pos] = byte('0' + n%10)
// 		n /= 10
// 	}

// 	return string(buf[pos:])
// }
