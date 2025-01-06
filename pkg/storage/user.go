package storage

import (
	"crypto/rsa"

	"golang.org/x/text/language"
)

type User struct {
	ID                string       `json:"id" yaml:"id"`
	Username          string       `json:"username" yaml:"username"`
	Password          string       `json:"password" yaml:"password"`
	Salt              string       `json:"salt" yaml:"salt"`
	FirstName         string       `json:"first_name" yaml:"first_name"`
	LastName          string       `json:"last_name" yaml:"last_name"`
	Email             string       `json:"email" yaml:"email"`
	EmailVerified     bool         `json:"email_verified" yaml:"email_verified"`
	Phone             string       `json:"phone" yaml:"phone"`
	PhoneVerified     bool         `json:"phone_verified" yaml:"phone_verified"`
	PreferredLanguage language.Tag `json:"preferred_language" yaml:"preferred_language"`
	IsAdmin           bool         `json:"is_admin" yaml:"is_admin"`
	Roles             []string     `json:"roles" yaml:"roles"`
}

type Service struct {
	keys map[string]*rsa.PublicKey
}

type UserStore interface {
	GetUserByID(string) *User
	GetUserByUsername(string) *User
	ExampleClientID() string
}

type userStore struct {
	users map[string]*User
}

func NewUserStore(issuer string, users []*User) UserStore {
	var userMap = make(map[string]*User)
	for _, user := range users {
		userMap[user.ID] = user
	}

	return userStore{
		users: userMap,
	}
}

// ExampleClientID is only used in the example server
func (u userStore) ExampleClientID() string {
	return "service"
}

func (u userStore) GetUserByID(id string) *User {
	return u.users[id]
}

func (u userStore) GetUserByUsername(username string) *User {
	for _, user := range u.users {
		if user.Username == username {
			return user
		}
	}
	return nil
}
