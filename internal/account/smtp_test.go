package account

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"io"
	"math/big"
	"net"
	"net/mail"
	"net/textproto"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"paradise-cosmetics-studio/internal/config"
)

type smtpCapture struct {
	data                     []byte
	authenticated, encrypted bool
}

// localSMTP owns its listener and accepted connection until test cleanup.
func localSMTP(t *testing.T, mode string, reject int, stall bool) (config.MailConfig, *tls.Config, <-chan smtpCapture) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "local SMTP test"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	serverTLS := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	host, portText, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	cfg := config.MailConfig{Mailer: "smtp", Host: host, Port: port, Encryption: mode, FromAddress: "sender@example.invalid", FromName: "Synthetic", SendTimeout: time.Second}
	if mode != "" {
		cfg.Username = "synthetic"
		cfg.Password = "synthetic-password"
	}
	captures := make(chan smtpCapture, 1)
	stop := make(chan struct{})
	var mutex sync.Mutex
	var accepted net.Conn
	var wg sync.WaitGroup
	wg.Add(1)
	t.Cleanup(func() {
		close(stop)
		listener.Close()
		mutex.Lock()
		if accepted != nil {
			accepted.Close()
		}
		mutex.Unlock()
		wg.Wait()
	})
	go func() {
		defer wg.Done()
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		mutex.Lock()
		accepted = conn
		mutex.Unlock()
		defer conn.Close()
		encrypted := false
		if mode == "ssl" {
			conn = tls.Server(conn, serverTLS)
			encrypted = true
		}
		reader := textproto.NewReader(bufio.NewReader(conn))
		writer := textproto.NewWriter(bufio.NewWriter(conn))
		if err = writer.PrintfLine("220 local SMTP"); err != nil {
			return
		}
		authenticated := false
		for {
			line, err := reader.ReadLine()
			if err != nil {
				return
			}
			command := strings.ToUpper(strings.SplitN(line, " ", 2)[0])
			switch command {
			case "EHLO":
				writer.PrintfLine("250-local")
				if mode == "tls" && !encrypted {
					writer.PrintfLine("250-STARTTLS")
				}
				writer.PrintfLine("250 AUTH PLAIN")
			case "HELO", "NOOP", "RSET":
				writer.PrintfLine("250 OK")
			case "STARTTLS":
				if err = writer.PrintfLine("220 Ready"); err != nil {
					return
				}
				conn = tls.Server(conn, serverTLS)
				encrypted = true
				reader = textproto.NewReader(bufio.NewReader(conn))
				writer = textproto.NewWriter(bufio.NewWriter(conn))
			case "AUTH":
				fields := strings.Fields(line)
				if len(fields) != 3 {
					writer.PrintfLine("535 authentication failed")
					continue
				}
				decoded, err := base64.StdEncoding.DecodeString(fields[2])
				authenticated = err == nil && string(decoded) == "\x00synthetic\x00synthetic-password"
				if authenticated {
					writer.PrintfLine("235 authenticated")
				} else {
					writer.PrintfLine("535 authentication failed")
				}
			case "MAIL":
				writer.PrintfLine("250 OK")
			case "RCPT":
				if stall {
					<-stop
					return
				}
				if reject != 0 {
					writer.PrintfLine("%d synthetic rejection", reject)
				} else {
					writer.PrintfLine("250 OK")
				}
			case "DATA":
				if err = writer.PrintfLine("354 Send data"); err != nil {
					return
				}
				data, err := io.ReadAll(reader.DotReader())
				if err != nil {
					return
				}
				captures <- smtpCapture{data, authenticated, encrypted}
				writer.PrintfLine("250 accepted")
			case "QUIT":
				writer.PrintfLine("221 goodbye")
				return
			default:
				writer.PrintfLine("500 unknown command")
			}
		}
	}()
	return cfg, &tls.Config{RootCAs: roots, ServerName: host, MinVersion: tls.VersionTLS12}, captures
}

func TestLocalSMTPTransport(t *testing.T) {
	for _, mode := range []string{"", "tls", "ssl"} {
		name := mode
		if name == "" {
			name = "plain"
		}
		t.Run(name, func(t *testing.T) {
			cfg, trust, messages := localSMTP(t, mode, 0, false)
			transport, err := NewSMTP(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if err = transport.client.SetTLSConfig(trust); err != nil {
				t.Fatal(err)
			}
			if err = transport.Send(context.Background(), Message{To: "recipient@example.invalid", Subject: "Synthetic subject", HTML: "<p>synthetic body</p>", ID: "mail:synthetic"}); err != nil {
				t.Fatal(err)
			}
			select {
			case capture := <-messages:
				if mode != "" && (!capture.authenticated || !capture.encrypted) {
					t.Fatal("TLS/AUTH missing")
				}
				parsed, err := mail.ReadMessage(bytes.NewReader(capture.data))
				if err != nil {
					t.Fatal(err)
				}
				if parsed.Header.Get("To") != "<recipient@example.invalid>" || parsed.Header.Get("Message-ID") == "" || !strings.Contains(parsed.Header.Get("Content-Type"), "text/html") {
					t.Fatal("MIME headers changed")
				}
			case <-t.Context().Done():
				t.Fatal("message was not captured")
			}
		})
	}
}

func TestLocalSMTPFailureClassification(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		code                 int
		stall, wantTemporary bool
	}{
		{"temporary", 451, false, true}, {"permanent", 550, false, false}, {"deadline", 0, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, _, _ := localSMTP(t, "", tc.code, tc.stall)
			if tc.stall {
				cfg.SendTimeout = 50 * time.Millisecond
			}
			transport, err := NewSMTP(cfg)
			if err != nil {
				t.Fatal(err)
			}
			err = transport.Send(context.Background(), Message{To: "recipient@example.invalid", Subject: "Synthetic", HTML: "synthetic", ID: "synthetic"})
			if err == nil || temporaryDelivery(err) != tc.wantTemporary {
				t.Fatalf("delivery classification mismatch (temporary=%v)", temporaryDelivery(err))
			}
		})
	}
}

func TestLocalSMTPRejectsUntrustedCertificate(t *testing.T) {
	cfg, _, _ := localSMTP(t, "tls", 0, false)
	transport, err := NewSMTP(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = transport.Send(context.Background(), Message{To: "recipient@example.invalid", Subject: "Synthetic", HTML: "synthetic", ID: "synthetic"}); err == nil {
		t.Fatal("untrusted TLS certificate accepted")
	}
}
