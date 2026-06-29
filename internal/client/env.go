package client

import (
	"crypto/tls"
	"crypto/x509"

	"google.golang.org/grpc"

	genezav1 "geneza.io/internal/pb/geneza/v1"
)

// Env bundles the loaded profile state every authenticated CLI command needs.
// Both the tenant CLI (geneza) and the cluster CLI (genezactl) build one per
// invocation from the named profile.
type Env struct {
	Store   *Store
	Profile *Profile
	Pool    *x509.CertPool
}

// LoadEnv loads the named profile, pins its CA pool, and returns the ready Env.
func LoadEnv(profile string) (*Env, error) {
	st, err := NewStore(profile)
	if err != nil {
		return nil, err
	}
	prof, err := st.LoadProfile()
	if err != nil {
		return nil, err
	}
	pool, err := st.LoadCAPool(prof.CASHA256)
	if err != nil {
		return nil, err
	}
	return &Env{Store: st, Profile: prof, Pool: pool}, nil
}

// DialUser opens the mTLS gRPC connection used by every post-login command. It
// also returns the client cert so a session command can follow a cross-
// controller redirect (re-dial the owner controller with the same identity).
func (e *Env) DialUser() (*grpc.ClientConn, genezav1.WorkspaceAPIClient, *tls.Certificate, error) {
	cert, _, err := e.Store.ClientCert()
	if err != nil {
		return nil, nil, nil, err
	}
	cc, err := DialController(e.Profile.ControllerGRPC, e.Pool, cert)
	if err != nil {
		return nil, nil, nil, err
	}
	return cc, genezav1.NewWorkspaceAPIClient(cc), cert, nil
}

// DialAdmin opens the mTLS gRPC connection for ClusterAPI calls.
func (e *Env) DialAdmin() (*grpc.ClientConn, genezav1.ClusterAPIClient, error) {
	cert, _, err := e.Store.ClientCert()
	if err != nil {
		return nil, nil, err
	}
	cc, err := DialController(e.Profile.ControllerGRPC, e.Pool, cert)
	if err != nil {
		return nil, nil, err
	}
	return cc, genezav1.NewClusterAPIClient(cc), nil
}
