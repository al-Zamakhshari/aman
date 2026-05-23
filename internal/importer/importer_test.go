package importer_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/al-Zamakhshari/aman/internal/importer"
)

const bitwardenJSON = `{
  "items": [
    {
      "type": 1,
      "name": "GitHub Deploy",
      "notes": "main deploy key",
      "login": {
        "username": "deploy@acme.com",
        "password": "gh-secret-123",
        "uris": [{"uri": "https://github.com"}],
        "totp": "JBSWY3DPEHPK3PXP"
      },
      "fields": [{"name": "team", "value": "platform"}]
    },
    {
      "type": 2,
      "name": "Secure Note",
      "notes": "this should be skipped"
    }
  ]
}`

const lastpassCSV = `url,username,password,totp,extra,name,grouping,fav
https://aws.amazon.com,root@acme.com,aws-pass,,prod notes,AWS Root,production,0
https://stripe.com,billing@acme.com,stripe-key,JBSWY3DPEHPK3PXP,,Stripe Live,payments,1
`

const genericCSV = `name,username,password,url,notes
my-service,alice@example.com,pass123,https://myservice.com,test entry
`

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	return path
}

func TestParseBitwarden(t *testing.T) {
	path := writeTemp(t, "bw.json", bitwardenJSON)

	records, err := importer.Import(path, importer.FormatBitwarden)
	if err != nil {
		t.Fatalf("Import bitwarden: %v", err)
	}

	// Secure note (type=2) must be skipped.
	if len(records) != 1 {
		t.Fatalf("expected 1 login record, got %d", len(records))
	}

	r := records[0]
	if r.Name != "github-deploy" {
		t.Errorf("Name = %q, want %q", r.Name, "github-deploy")
	}
	if r.Payload.Username != "deploy@acme.com" {
		t.Errorf("Username = %q", r.Payload.Username)
	}
	if r.Payload.Password != "gh-secret-123" {
		t.Errorf("Password = %q", r.Payload.Password)
	}
	if r.Payload.URL != "https://github.com" {
		t.Errorf("URL = %q", r.Payload.URL)
	}
	if r.Payload.TOTPSecret != "JBSWY3DPEHPK3PXP" {
		t.Errorf("TOTP = %q", r.Payload.TOTPSecret)
	}
	if r.Payload.Notes != "main deploy key" {
		t.Errorf("Notes = %q", r.Payload.Notes)
	}
	if r.Payload.Fields["team"] != "platform" {
		t.Errorf("custom field team = %q", r.Payload.Fields["team"])
	}
}

func TestParseLastPass(t *testing.T) {
	path := writeTemp(t, "lp.csv", lastpassCSV)

	records, err := importer.Import(path, importer.FormatLastPass)
	if err != nil {
		t.Fatalf("Import lastpass: %v", err)
	}

	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}

	aws := records[0]
	if aws.Name != "aws-root" {
		t.Errorf("Name = %q, want %q", aws.Name, "aws-root")
	}
	if aws.Payload.Password != "aws-pass" {
		t.Errorf("Password = %q", aws.Payload.Password)
	}
	if len(aws.Tags) == 0 || aws.Tags[0] != "production" {
		t.Errorf("Tags = %v, want [production]", aws.Tags)
	}

	stripe := records[1]
	if stripe.Payload.TOTPSecret != "JBSWY3DPEHPK3PXP" {
		t.Errorf("Stripe TOTP = %q", stripe.Payload.TOTPSecret)
	}
}

func TestParseGenericCSV(t *testing.T) {
	path := writeTemp(t, "generic.csv", genericCSV)

	records, err := importer.Import(path, importer.FormatCSV)
	if err != nil {
		t.Fatalf("Import csv: %v", err)
	}

	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}

	r := records[0]
	if r.Name != "my-service" {
		t.Errorf("Name = %q", r.Name)
	}
	if r.Payload.Username != "alice@example.com" {
		t.Errorf("Username = %q", r.Payload.Username)
	}
}

func TestDetectFormat(t *testing.T) {
	cases := []struct {
		file   string
		expect importer.Format
	}{
		{"export.csv", importer.FormatLastPass},
	}
	for _, c := range cases {
		got := importer.DetectFormat(c.file)
		if got != c.expect {
			t.Errorf("DetectFormat(%q) = %q, want %q", c.file, got, c.expect)
		}
	}
}
