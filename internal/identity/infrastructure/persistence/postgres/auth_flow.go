package postgres

// func (p *Postgres) GetAuthFlowByID(ctx context.Context, id int64) (domain.AuthFlow, error) {
// 	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "GetAuthFlowByID")
// 	defer span.End()

// 	row, err := p.query.GetAuthFlowByID(ctx, id)
// 	if err != nil {
// 		if errors.Is(err, pgx.ErrNoRows) {
// 			return domain.AuthFlow{}, domain.ErrAuthFlowNotFound
// 		}
// 		return domain.AuthFlow{}, err
// 	}
// 	var ctxMap map[string]any
// 	if len(row.Context) > 0 {
// 		_ = json.Unmarshal(row.Context, &ctxMap)
// 	}
// 	if ctxMap == nil {
// 		ctxMap = make(map[string]any)
// 	}
// 	return domain.AuthFlow{
// 		ID:          row.ID,
// 		UserID:      fromPgInt8(row.UserID),
// 		FlowType:    domain.AuthFlowType(row.FlowType),
// 		FlowState:   domain.AuthFlowState(row.FlowState),
// 		IPAddress:   fromPgText(row.IpAddress),
// 		UserAgent:   fromPgText(row.UserAgent),
// 		Context:     ctxMap,
// 		CreatedAt:   row.CreatedAt.Time,
// 		ExpiresAt:   row.ExpiresAt.Time,
// 		CompletedAt: fromPgTz(row.CompletedAt),
// 	}, nil
// }

// func (p *Postgres) UpdateAuthFlow(ctx context.Context, flow domain.AuthFlow) error {
// 	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "UpdateAuthFlow")
// 	defer span.End()

// 	ctxJSON, _ := json.Marshal(flow.Context)
// 	if ctxJSON == nil {
// 		ctxJSON = []byte(`{}`)
// 	}
// 	return p.query.UpdateAuthFlow(ctx, sqlc.UpdateAuthFlowParams{
// 		ID:          flow.ID,
// 		FlowState:   int16(flow.FlowState),
// 		Context:     ctxJSON,
// 		CompletedAt: pgTzPtr(flow.CompletedAt),
// 	})
// }

// func (p *Postgres) DeleteExpiredAuthFlows(ctx context.Context) (int64, error) {
// 	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "DeleteExpiredAuthFlows")
// 	defer span.End()

// 	tag, err := p.conn.Exec(ctx, `DELETE FROM auth_flows WHERE expires_at < NOW() AND completed_at IS NULL`)
// 	if err != nil {
// 		return 0, err
// 	}
// 	return tag.RowsAffected(), nil
// }
