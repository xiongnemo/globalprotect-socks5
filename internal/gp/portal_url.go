package gp

import "net"

func (u PortalURL) Scheme() string {
	return u.raw.Scheme
}

func (u PortalURL) Hostname() string {
	return u.raw.Hostname()
}

func (u PortalURL) TCPAddress() string {
	port := u.raw.Port()
	if port == "" {
		port = "443"
		if u.raw.Scheme == "http" {
			port = "80"
		}
	}
	return net.JoinHostPort(u.raw.Hostname(), port)
}
