package account

import (
	"bytes"
	"context"
	"errors"
	"net/mail"
	"net/textproto"
	"regexp"
	"testing"

	"blessing-skin-go/internal/config"
	gomail "github.com/wneessen/go-mail"
)

func TestSMTPMessageIDIsValidStableAndHasNoOperationKeyPunctuation(t *testing.T) {
	smtp := &SMTP{cfg: config.MailConfig{FromName: "Example", FromAddress: "sender@example.invalid"}}
	message := Message{To: "recipient@example.invalid", Subject: "Subject", HTML: "<p>body</p>", ID: "mail:0123456789"}
	first, err := smtp.message(message)
	if err != nil {
		t.Fatal(err)
	}
	second, err := smtp.message(message)
	if err != nil {
		t.Fatal(err)
	}
	var buffer bytes.Buffer
	if _, err = first.WriteTo(&buffer); err != nil {
		t.Fatal(err)
	}
	parsed, err := mail.ReadMessage(&buffer)
	if err != nil {
		t.Fatal(err)
	}
	id := parsed.Header.Get("Message-ID")
	if !regexp.MustCompile(`^<[a-f0-9]{64}@blessing-skin>$`).MatchString(id) || first.GetMessageID() != second.GetMessageID() {
		t.Fatal("invalid or unstable Message-ID")
	}
}
func TestSMTPTransportFailuresRetainRetrySemantics(t *testing.T) {
	for _, reason := range []gomail.SendErrReason{gomail.ErrSMTPMailFrom, gomail.ErrSMTPRcptTo, gomail.ErrSMTPData, gomail.ErrSMTPDataClose, gomail.ErrSMTPReset, gomail.ErrWriteContent, gomail.ErrConnCheck} {
		if !temporaryDelivery(&gomail.SendError{Reason: reason}) {
			t.Fatalf("transport failure %v permanently blocked", reason)
		}
	}
	for _, reason := range []gomail.SendErrReason{gomail.ErrGetSender, gomail.ErrGetRcpts, gomail.ErrNoUnencoded} {
		if temporaryDelivery(&gomail.SendError{Reason: reason}) {
			t.Fatalf("configuration failure %v retried", reason)
		}
	}
	for _, test := range []struct {
		err       error
		temporary bool
	}{{&textproto.Error{Code: 451, Msg: "synthetic temporary"}, true}, {&textproto.Error{Code: 550, Msg: "synthetic permanent"}, false}, {context.DeadlineExceeded, true}, {errors.New("synthetic payload error"), false}} {
		if temporaryDelivery(test.err) != test.temporary {
			t.Fatal("delivery classification changed")
		}
	}
}
