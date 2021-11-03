package auth

import (
	"encoding/json"

	"github.com/gtosh4/unity_lan/pkg/credstore"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"
)

type TokenSecret struct {
	Secret credstore.Secret

	Token oauth2.Token
}

func (s *TokenSecret) Load() error {
	err := s.Secret.Load()
	if err != nil {
		return err
	}

	if s.Secret.Value == "" {
		return nil
	}

	err = json.Unmarshal([]byte(s.Secret.Value), &s.Token)
	if err != nil {
		return errors.Wrapf(err, "Could not unmarshal value: '%s'", s.Secret.Value)
	}

	return nil
}

func (s *TokenSecret) Save() error {
	v, err := json.Marshal(s.Token)
	if err != nil {
		return err
	}
	s.Secret.Value = string(v)
	return s.Secret.Save()
}
