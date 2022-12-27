package vhostmanager

import (
	"crypto/tls"
	"math/rand"
	"net/http/httputil"
	"sync"
)

// Host represents a target host of a proxy
type Host struct {
	Address        string // e.g. "host:port" or ":port" for localhost port
	GetCertificate func() (*tls.Certificate, error)
	ReverseProxy   *httputil.ReverseProxy
}

// HostManager represents the host-management functionality required of a multiple-host proxy
type HostManager interface {
	PutHost(sni string, addr []string, getCertificateFn func() (*tls.Certificate, error), rp *httputil.ReverseProxy) error
	GetHost(sni string) (*Host, bool, error)
	RemoveHost(sni string) error
}

// InMemoryHostManager is an in-memory implementation of the HostManager iface
type InMemoryHostManager struct {
	sync.RWMutex // inherit read/write lock behavior
	hosts        map[string]*Host
}

// ensure InMemoryTargetStorage implements HostManager at compile-time
var _ HostManager = (*InMemoryHostManager)(nil)

// NewInMemoryHostManager is the InMemoryHostManager constructor
func NewInMemoryHostManager() *InMemoryHostManager {
	return &InMemoryHostManager{
		hosts: make(map[string]*Host),
	}
}

// PutHost adds/updates the target host for a given server name
func (s *InMemoryHostManager) PutHost(
	sni string,
	addr []string,
	getCertificateFn func() (*tls.Certificate, error),
	rp *httputil.ReverseProxy,
) error {
	s.Lock()
	defer s.Unlock()
	// pick a random upstream
	upstream := addr[rand.Intn(len(addr))]

	s.hosts[sni] = &Host{
		Address:        upstream,
		GetCertificate: getCertificateFn,
		ReverseProxy:   rp,
	}
	return nil
}

// GetHost looks-up the target host for a given server name
func (s *InMemoryHostManager) GetHost(sni string) (*Host, bool, error) {
	s.RLock()
	defer s.RUnlock()

	t, ok := s.hosts[sni]
	return t, ok, nil
}

// RemoveHost removes the target host for a given server name
func (s *InMemoryHostManager) RemoveHost(sni string) error {
	s.Lock()
	defer s.Unlock()

	delete(s.hosts, sni)
	return nil
}
