package account

import (
	"context"
	"crypto/cipher"
	"crypto/tls"
	"database/sql"
	"errors"
	"fmt"
	"html"
	"net"
	"net/textproto"
	"strings"
	"time"

	"blessing-skin-go/internal/config"
	"blessing-skin-go/internal/identity"
	"blessing-skin-go/internal/outbox"
	"blessing-skin-go/internal/site"
	gomail "github.com/wneessen/go-mail"
)

type Message struct{ To, Subject, HTML, ID string }
type Transport interface {
	Send(context.Context, Message) error
}
type Mail struct {
	cipher                  cipher.AEAD
	BaseURL, FallbackLocale string
	Site                    *site.Service
	Messages                map[string]map[string]any
	Transport               Transport
	RetryDelay              time.Duration
}

func NewMail(key []byte, baseURL, fallback string, view *site.Service, messages map[string]map[string]any, transport Transport, retry time.Duration) (*Mail, error) {
	aead, err := mailCipher(key)
	if err != nil {
		return nil, err
	}
	return &Mail{aead, baseURL, fallback, view, messages, transport, retry}, nil
}
func (m *Mail) Handler(s *Service) outbox.Handler {
	return func(ctx context.Context, task outbox.Task) error {
		p, err := m.open(task.Payload)
		if err != nil {
			return &outbox.DeliveryFailure{Class: "mail_payload"}
		}
		// A stale queued message is obsolete. It never gets a replacement token.
		_, err = s.InspectChallenge(ctx, p.UID, p.Purpose, p.Token)
		if errors.Is(err, ErrInvalidChallenge) {
			return nil
		}
		if err != nil {
			return err
		}
		var email string
		var version int64
		err = s.Store.DB.QueryRowContext(ctx, "SELECT target_email,version FROM "+s.Store.Table("go_mail_challenges")+" WHERE digest=?", identity.Digest(p.Token)).Scan(&email, &version)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if email != p.Email || version != p.Version {
			return &outbox.DeliveryFailure{Class: "mail_payload"}
		}
		path := "reset"
		prefix := "auth.forgot.mail."
		if p.Purpose == "verify" {
			path = "verify"
			prefix = "user.verification.mail."
		}
		link := fmt.Sprintf("%s/auth/%s/%d?token=%s", m.BaseURL, path, p.UID, p.Token)
		translations, err := m.Site.Translations(ctx, p.Locale, m.FallbackLocale, m.Messages)
		if err != nil {
			return err
		}
		options, err := m.Site.Options(ctx)
		if err != nil {
			return err
		}
		name, _ := site.LocalizedOption(options, "site_name", p.Locale).(string)
		text := func(key string) string { return messageText(translations, prefix+key) }
		subject := strings.ReplaceAll(text("title"), ":sitename", name)
		body := ""
		for _, key := range []string{"message", "reset", "ignore"} {
			value := strings.NewReplacer(":sitename", html.EscapeString(name), ":url", html.EscapeString(link)).Replace(text(key))
			body += "<p>" + value + "</p>\n"
		}
		if err = m.Transport.Send(ctx, Message{p.Email, subject, body, task.OperationKey}); err != nil {
			temporary := temporaryDelivery(err)
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if temporary {
				return &outbox.DeliveryFailure{Class: "mail_temporary", Delay: m.RetryDelay}
			}
			return &outbox.DeliveryFailure{Class: "mail_permanent"}
		}
		return nil
	}
}
func messageText(messages map[string]any, key string) string {
	var value any = messages
	for _, part := range strings.Split(key, ".") {
		table, ok := value.(map[string]any)
		if !ok {
			return key
		}
		value = table[part]
	}
	text, ok := value.(string)
	if !ok {
		return key
	}
	return text
}

// NewTransportFunc lets tests substitute the SMTP transport without touching
// production code paths; both the HTTP server and the worker build their mail
// transport through the same factory.
type NewTransportFunc func(config.MailConfig) (Transport, error)

// DefaultTransport is the production factory.
var DefaultTransport NewTransportFunc = func(c config.MailConfig) (Transport, error) {
	return NewSMTP(c)
}

type SMTP struct {
	client *gomail.Client
	cfg    config.MailConfig
}

func NewSMTP(c config.MailConfig) (*SMTP, error) {
	if c.Mailer != "smtp" {
		return nil, errors.New("account: unsupported configured mailer")
	}
	options := []gomail.Option{gomail.WithPort(c.Port), gomail.WithTimeout(c.SendTimeout)}
	switch c.Encryption {
	case "tls":
		options = append(options, gomail.WithTLSPolicy(gomail.TLSMandatory))
	case "ssl":
		options = append(options, gomail.WithSSL())
	case "":
		options = append(options, gomail.WithTLSPolicy(gomail.NoTLS))
	default:
		return nil, errors.New("account: unsupported MAIL_ENCRYPTION")
	}
	if c.Username != "" {
		options = append(options, gomail.WithUsername(c.Username), gomail.WithPassword(c.Password), gomail.WithSMTPAuth(gomail.SMTPAuthAutoDiscover))
	}
	client, err := gomail.NewClient(c.Host, options...)
	if err != nil {
		return nil, errors.New("account: invalid SMTP configuration")
	}
	return &SMTP{client, c}, nil
}

// SetTLSConfig installs a custom TLS root pool. It exists for local acceptance
// runs against a loopback simulator; production configuration never calls it.
func (s *SMTP) SetTLSConfig(config *tls.Config) error { return s.client.SetTLSConfig(config) }

func (s *SMTP) message(message Message) (*gomail.Msg, error) {
	msg := gomail.NewMsg()
	if err := msg.FromFormat(s.cfg.FromName, s.cfg.FromAddress); err != nil {
		return nil, errors.New("account: invalid mail sender")
	}
	if err := msg.To(message.To); err != nil {
		return nil, errors.New("account: invalid mail recipient")
	}
	msg.Subject(message.Subject)
	msg.SetBodyString(gomail.TypeTextHTML, message.HTML)
	msg.SetMessageIDWithValue(fmt.Sprintf("%x@blessing-skin", identity.Digest(message.ID)))
	return msg, nil
}

func (s *SMTP) Send(ctx context.Context, message Message) error {
	msg, err := s.message(message)
	if err != nil {
		return err
	}
	deadline, cancel := context.WithTimeout(ctx, s.cfg.SendTimeout)
	defer cancel()
	return s.client.DialAndSendWithContext(deadline, msg)
}

// go-mail's SendError does not unwrap its transport cause. For SMTP commands
// and content transfer, code 0 means no server reply was available.
func temporaryDelivery(err error) bool {
	var send *gomail.SendError
	if errors.As(err, &send) {
		if code := send.ErrorCode(); code != 0 {
			return code >= 400 && code < 500
		}
		if send.IsTemp() {
			return true
		}
		switch send.Reason {
		case gomail.ErrSMTPMailFrom, gomail.ErrSMTPRcptTo, gomail.ErrSMTPData, gomail.ErrSMTPDataClose, gomail.ErrSMTPReset, gomail.ErrWriteContent, gomail.ErrConnCheck:
			return true
		}
		return false
	}
	var smtp *textproto.Error
	if errors.As(err, &smtp) {
		return smtp.Code >= 400 && smtp.Code < 500
	}
	var network net.Error
	return errors.As(err, &network) || errors.Is(err, context.DeadlineExceeded)
}
