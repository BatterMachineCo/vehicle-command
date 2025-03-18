package main

import (
	"net/http"
)

// Since the proxy just listens on localhost, a self-signed certificate shouldn't present any
// issues.

func NewServer(addr string) *http.Server {

	server := &http.Server{
		Addr: addr,
	}
	return server
}
