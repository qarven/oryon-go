package paginate

const (
	defaultLimit = 10
	maxLimit     = 100
)

// Normalize clamps limit to [1, maxLimit] and converts the 1-based page
// number into a SQL offset.
func Normalize(limit, page int32) (int32, int32) {
	if limit <= 0 {
		limit = defaultLimit
	}

	if limit > maxLimit {
		limit = maxLimit
	}

	if page < 1 {
		page = 1
	}

	offset := (page - 1) * limit

	return limit, offset
}