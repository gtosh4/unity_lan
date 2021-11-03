package credstore

import "github.com/docker/docker-credential-helpers/osxkeychain"

var impl = osxkeychain.Osxkeychain{}
