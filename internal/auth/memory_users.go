package auth

import (
	"errors"
	"strings"
	"sync"
)

var ErrUserNotFound = errors.New("user not found")

type MemoryUserStore struct {
	mu    sync.RWMutex
	users map[string]User
}

func NewMemoryUserStore() *MemoryUserStore {
	return &MemoryUserStore{
		users: make(map[string]User),
	}
}

func (s *MemoryUserStore) Add(user User) {
	s.mu.Lock()
	defer s.mu.Unlock()

	email := strings.ToLower(strings.TrimSpace(user.Email))
	user.Email = email
	user.PasswordHash = append([]byte(nil), user.PasswordHash...)
	user.Scopes = append([]string(nil), user.Scopes...)

	s.users[email] = user
}

func (s *MemoryUserStore) FindByEmail(email string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	user, ok := s.users[strings.ToLower(strings.TrimSpace(email))]
	if !ok {
		return nil, ErrUserNotFound
	}

	copyOfUser := user
	copyOfUser.PasswordHash = append([]byte(nil), user.PasswordHash...)
	copyOfUser.Scopes = append([]string(nil), user.Scopes...)

	return &copyOfUser, nil
}

func (s *MemoryUserStore) FindByID(id string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, user := range s.users {
		if user.ID == id {
			copyOfUser := user
			copyOfUser.PasswordHash = append([]byte(nil), user.PasswordHash...)
			copyOfUser.Scopes = append([]string(nil), user.Scopes...)
			return &copyOfUser, nil
		}
	}
	return nil, ErrUserNotFound
}
