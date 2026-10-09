package mq

const (
	identityRegistrationSource   = "identity.registration"
	identityRegistrationConsumer = "identity.registration.notification"

	identityPasswordResetSource   = "identity.password_reset"
	identityPasswordResetConsumer = "identity.password_reset.notification"
)

type EventRegistrationMessage struct {
	Name     string `json:"name"`
	Identity string `json:"identity"`
	Channel  string `json:"channel"` // emial, phone
	Code     string `json:"code"`
}

type EventPasswordResetMessage struct {
	Name     string `json:"name"`
	Identity string `json:"identity"`
	Channel  string `json:"channel"` // email
	Token    string `json:"token"`
}
