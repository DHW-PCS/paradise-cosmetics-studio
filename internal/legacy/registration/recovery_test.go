package registration

import "testing"

func TestProviderRecoveryNeverInfersSubjectFromEmail(t *testing.T) {
	for _, tc := range []struct {
		provider, subject string
		installed         []string
		mapped, local     bool
		want              string
	}{
		{"github", "subject", nil, false, true, "provider_unavailable"},
		{"github", "", []string{"github"}, false, true, "new_provider_challenge"},
		{"github", "known", []string{"github"}, true, false, "mapped_subject"},
		{"github", "new", []string{"github"}, false, true, "authenticate_existing_then_bind"},
		{"github", "new", []string{"github"}, false, false, "recover_current_mailbox_then_explicit_bind"},
	} {
		if got := ProviderRecovery(tc.provider, tc.subject, tc.installed, tc.mapped, tc.local); got != tc.want {
			t.Fatalf("recovery %s", got)
		}
	}
}
