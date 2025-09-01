package socks5

// CredentialStore defines the interface for validating user credentials.
// Implementations should return true if the username/password combination is valid.
type CredentialStore interface {
	// Valid checks if the provided username and password are valid
	Valid(user, password string) bool
}

// StaticCredentials enables using a map directly as a credential store.
// The map keys are usernames and values are passwords.
type StaticCredentials map[string]string

// Valid checks if the provided username exists and the password matches.
func (s StaticCredentials) Valid(user, password string) bool {
	pass, ok := s[user]
	if !ok {
		return false
	}
	return password == pass
}
