package domain

type ListUsersArgument struct {
	Email  string
	Name   string
	Limit  int32
	Offset int32
}
