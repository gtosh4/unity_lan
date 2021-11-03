package credstore

import (
	"github.com/docker/docker-credential-helpers/credentials"
)

func Add(c *credentials.Credentials) error {
	return impl.Add(c)
}

func Delete(serverURL string) error {
	return impl.Delete(serverURL)
}

func Get(serverURL string) (*credentials.Credentials, error) {
	cred := &credentials.Credentials{
		ServerURL: serverURL,
	}
	var err error
	cred.Username, cred.Secret, err = impl.Get(serverURL)
	return cred, err
}

func List() (map[string]string, error) {
	return impl.List()
}

type Secret struct {
	Name     string
	Username string
	Value    string
}

func (s *Secret) Load() error {
	cred, err := Get(s.Name)
	if err != nil {
		return err
	}
	s.Username = cred.Username
	s.Value = cred.Secret

	return nil
}

func (s *Secret) Save() error {
	return Add(&credentials.Credentials{
		ServerURL: s.Name,
		Username:  s.Username,
		Secret:    s.Value,
	})
}
