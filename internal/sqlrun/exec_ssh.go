package sqlrun

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

// SSHConfig describes how to reach the host that holds the pgs database.
type SSHConfig struct {
	Host           string
	Port           int
	User           string
	PrivateKey     []byte // PEM; when empty, ssh-agent (SSH_AUTH_SOCK) is used
	Passphrase     []byte // decrypts PrivateKey when it is passphrase protected
	KnownHostsFile string // default ~/.ssh/known_hosts
	HostKey        string // authorized_keys-format pin; takes precedence over known hosts
	InsecureHost   bool   // skip host key verification
}

// SSHExec runs commands on a remote host over SSH (native Go client).
type SSHExec struct{ Cfg SSHConfig }

func (s SSHExec) Describe() string {
	return fmt.Sprintf("%s@%s:%d", s.Cfg.User, s.Cfg.Host, s.port())
}

func (s SSHExec) port() int {
	if s.Cfg.Port == 0 {
		return 22
	}
	return s.Cfg.Port
}

// ExpandHome expands a leading "~/" to the user's home directory.
func ExpandHome(path string) (string, error) {
	if !strings.HasPrefix(path, "~/") {
		return path, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, path[2:]), nil
}

// hostKeyAlgos lists the signature algorithms under which a host key of one of the given types
// is presented. Without restricting the client to them, Go offers its own preference order and a
// server holding several host keys may answer with one that does not match the pin or the
// known_hosts entry, which is then reported as a host key mismatch.
func hostKeyAlgos(types ...string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(a string) {
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	for _, t := range types {
		if t == ssh.KeyAlgoRSA {
			add(ssh.KeyAlgoRSASHA512)
			add(ssh.KeyAlgoRSASHA256)
		}
		add(t)
	}
	return out
}

func (s SSHExec) clientConfig() (*ssh.ClientConfig, func(), error) {
	cleanup := func() {}
	var auth []ssh.AuthMethod
	if len(s.Cfg.PrivateKey) > 0 {
		var signer ssh.Signer
		var err error
		if len(s.Cfg.Passphrase) > 0 {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(s.Cfg.PrivateKey, s.Cfg.Passphrase)
		} else {
			signer, err = ssh.ParsePrivateKey(s.Cfg.PrivateKey)
			var missing *ssh.PassphraseMissingError
			if errors.As(err, &missing) {
				return nil, cleanup, errors.New("the ssh private key is passphrase protected: set ssh.private_key_passphrase (or PGS_SSH_PRIVATE_KEY_PASSPHRASE), or load the key into an ssh-agent")
			}
		}
		if err != nil {
			return nil, cleanup, fmt.Errorf("parse ssh private key: %w", err)
		}
		auth = append(auth, ssh.PublicKeys(signer))
	} else if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		conn, err := net.Dial("unix", sock)
		if err != nil {
			return nil, cleanup, fmt.Errorf("connect to ssh-agent: %w", err)
		}
		cleanup = func() { _ = conn.Close() }
		auth = append(auth, ssh.PublicKeysCallback(agent.NewClient(conn).Signers))
	} else {
		return nil, cleanup, errors.New("no ssh credentials: set ssh.private_key / ssh.private_key_file or run an ssh-agent (SSH_AUTH_SOCK)")
	}

	var hk ssh.HostKeyCallback
	var algos []string
	switch {
	case s.Cfg.HostKey != "":
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(s.Cfg.HostKey))
		if err != nil {
			return nil, cleanup, fmt.Errorf("parse ssh.host_key: %w", err)
		}
		hk = ssh.FixedHostKey(pub)
		algos = hostKeyAlgos(pub.Type())
	case s.Cfg.InsecureHost:
		hk = ssh.InsecureIgnoreHostKey() //nolint:gosec // explicit opt-in
	default:
		file := s.Cfg.KnownHostsFile
		if file == "" {
			file = "~/.ssh/known_hosts"
		}
		file, err := ExpandHome(file)
		if err != nil {
			return nil, cleanup, err
		}
		cb, err := knownhosts.New(file)
		if err != nil {
			return nil, cleanup, fmt.Errorf("load known_hosts %q (or set ssh.host_key): %w", file, err)
		}
		hk = cb
	}
	return &ssh.ClientConfig{User: s.Cfg.User, Auth: auth, HostKeyCallback: hk, HostKeyAlgorithms: algos, Timeout: 30 * time.Second}, cleanup, nil
}

// connect dials and performs the handshake. When the known_hosts check fails because the server
// presented a host key of another type than the one on record, it retries once, asking the server
// for the recorded key type(s).
func (s SSHExec) connect(ctx context.Context) (*ssh.Client, func(), error) {
	addr := net.JoinHostPort(s.Cfg.Host, strconv.Itoa(s.port()))
	var algos []string
	for attempt := 0; ; attempt++ {
		cc, cleanup, err := s.clientConfig()
		if err != nil {
			cleanup()
			return nil, func() {}, err
		}
		if algos != nil {
			cc.HostKeyAlgorithms = algos
		}
		nc, err := (&net.Dialer{Timeout: cc.Timeout}).DialContext(ctx, "tcp", addr)
		if err != nil {
			cleanup()
			return nil, func() {}, fmt.Errorf("dial %s: %w", addr, err)
		}
		// Closing the connection is what interrupts a handshake or a running command.
		stop := context.AfterFunc(ctx, func() { _ = nc.Close() })
		_ = nc.SetDeadline(time.Now().Add(cc.Timeout)) // bounds the handshake only
		sc, chans, reqs, err := ssh.NewClientConn(nc, addr, cc)
		if err != nil {
			stop()
			_ = nc.Close()
			cleanup()
			if ctx.Err() != nil {
				return nil, func() {}, ctx.Err()
			}
			var ke *knownhosts.KeyError
			if attempt == 0 && errors.As(err, &ke) && len(ke.Want) > 0 {
				var types []string
				for _, w := range ke.Want {
					types = append(types, w.Key.Type())
				}
				algos = hostKeyAlgos(types...)
				continue
			}
			return nil, func() {}, fmt.Errorf("ssh handshake with %s: %w", addr, err)
		}
		_ = nc.SetDeadline(time.Time{})
		client := ssh.NewClient(sc, chans, reqs)
		return client, func() { stop(); _ = client.Close(); cleanup() }, nil
	}
}

func (s SSHExec) Run(ctx context.Context, command string, stdin []byte) ([]byte, []byte, error) {
	client, closeAll, err := s.connect(ctx)
	defer closeAll()
	if err != nil {
		return nil, nil, err
	}
	sess, err := client.NewSession()
	if err != nil {
		return nil, nil, err
	}
	defer sess.Close()

	var out, errb bytes.Buffer
	sess.Stdin = bytes.NewReader(stdin)
	sess.Stdout, sess.Stderr = &out, &errb
	err = sess.Run(command)
	if ctx.Err() != nil {
		return nil, nil, ctx.Err()
	}
	return out.Bytes(), errb.Bytes(), err
}
