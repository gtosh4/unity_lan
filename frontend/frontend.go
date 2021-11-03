package frontend

import (
	_ "embed"
)

//go:embed public/build/bundle.js
var Javascript string

//go:embed public/build/bundle.css
var CSS string

//go:embed public/AuthSuccess.html
var AuthSuccess []byte
