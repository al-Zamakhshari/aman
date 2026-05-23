// Package importer converts exported data from popular password managers
// into aman Payload slices, ready to be sealed into a vault.
package importer

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/al-Zamakhshari/aman/internal/entry"
)

// Record is a normalised credential ready for import.
type Record struct {
	Name     string
	Payload  *entry.Payload
	Tags     []string
}

// Format identifies the source password manager.
type Format string

const (
	FormatBitwarden  Format = "bitwarden"
	FormatOnePassword Format = "1password"
	FormatLastPass   Format = "lastpass"
	FormatCSV        Format = "csv" // generic aman CSV: name,username,password,url,notes
)

// DetectFormat guesses the format from the file extension and content.
func DetectFormat(path string) Format {
	lower := strings.ToLower(path)
	switch {
	case strings.HasSuffix(lower, ".json"):
		// Peek at the JSON to tell Bitwarden from 1Password.
		f, err := os.Open(path) //nolint:gosec
		if err != nil {
			return FormatCSV
		}
		defer f.Close()
		var peek map[string]json.RawMessage
		if json.NewDecoder(io.LimitReader(f, 512)).Decode(&peek) == nil {
			if _, ok := peek["encrypted"]; ok {
				return FormatBitwarden
			}
			if _, ok := peek["accounts"]; ok {
				return FormatOnePassword
			}
			if _, ok := peek["items"]; ok {
				return FormatBitwarden
			}
		}
		return FormatBitwarden
	case strings.HasSuffix(lower, ".csv"):
		return FormatLastPass // or generic; we try lastpass header first
	default:
		return FormatCSV
	}
}

// Import parses a password manager export file and returns normalised records.
func Import(path string, format Format) ([]Record, error) {
	f, err := os.Open(path) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	switch format {
	case FormatBitwarden:
		return parseBitwarden(f)
	case FormatOnePassword:
		return parseOnePassword(f)
	case FormatLastPass:
		return parseLastPass(f)
	default:
		return parseGenericCSV(f)
	}
}

// ── Bitwarden ────────────────────────────────────────────────────────────────

type bitwardenExport struct {
	Items []bitwardenItem `json:"items"`
}

type bitwardenItem struct {
	Name   string           `json:"name"`
	Type   int              `json:"type"` // 1=login, 2=secure note, 3=card, 4=identity
	Login  *bitwardenLogin  `json:"login,omitempty"`
	Notes  string           `json:"notes,omitempty"`
	Fields []bitwardenField `json:"fields,omitempty"`
	FolderID string         `json:"folderId,omitempty"`
}

type bitwardenLogin struct {
	Username string `json:"username"`
	Password string `json:"password"`
	URIs     []struct {
		URI string `json:"uri"`
	} `json:"uris,omitempty"`
	TOTP string `json:"totp,omitempty"`
}

type bitwardenField struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func parseBitwarden(r io.Reader) ([]Record, error) {
	var export bitwardenExport
	if err := json.NewDecoder(r).Decode(&export); err != nil {
		return nil, fmt.Errorf("parse bitwarden JSON: %w", err)
	}

	var records []Record
	for _, item := range export.Items {
		if item.Type != 1 || item.Login == nil {
			continue // skip non-login items
		}

		url := ""
		if len(item.Login.URIs) > 0 {
			url = item.Login.URIs[0].URI
		}

		fields := map[string]string{}
		for _, f := range item.Fields {
			if f.Name != "" && f.Value != "" {
				fields[f.Name] = f.Value
			}
		}

		records = append(records, Record{
			Name: sanitiseName(item.Name),
			Payload: &entry.Payload{
				Username:   item.Login.Username,
				Password:   item.Login.Password,
				URL:        url,
				TOTPSecret: item.Login.TOTP,
				Notes:      item.Notes,
				Fields:     fields,
			},
		})
	}
	return records, nil
}

// ── 1Password ────────────────────────────────────────────────────────────────

type opExport struct {
	Accounts []opAccount `json:"accounts"`
}

type opAccount struct {
	Vaults []opVault `json:"vaults"`
}

type opVault struct {
	Items []opItem `json:"items"`
}

type opItem struct {
	Title    string    `json:"title"`
	Category string    `json:"category"`
	Fields   []opField `json:"fields"`
	Tags     []string  `json:"tags,omitempty"`
}

type opField struct {
	Label   string `json:"label"`
	Value   string `json:"value"`
	Type    string `json:"type"`
	Purpose string `json:"purpose,omitempty"` // USERNAME, PASSWORD, NOTES
}

func parseOnePassword(r io.Reader) ([]Record, error) {
	var export opExport
	if err := json.NewDecoder(r).Decode(&export); err != nil {
		return nil, fmt.Errorf("parse 1password JSON: %w", err)
	}

	var records []Record
	for _, account := range export.Accounts {
		for _, vault := range account.Vaults {
			for _, item := range vault.Items {
				if strings.EqualFold(item.Category, "secure note") {
					continue
				}

				p := &entry.Payload{Fields: map[string]string{}}
				for _, f := range item.Fields {
					switch f.Purpose {
					case "USERNAME":
						p.Username = f.Value
					case "PASSWORD":
						p.Password = f.Value
					case "NOTES":
						p.Notes = f.Value
					default:
						if f.Value != "" {
							p.Fields[f.Label] = f.Value
						}
					}
					if strings.EqualFold(f.Label, "website") || strings.EqualFold(f.Label, "url") {
						p.URL = f.Value
					}
					if strings.EqualFold(f.Type, "totp") {
						p.TOTPSecret = f.Value
					}
				}

				records = append(records, Record{
					Name:    sanitiseName(item.Title),
					Payload: p,
					Tags:    item.Tags,
				})
			}
		}
	}
	return records, nil
}

// ── LastPass CSV ─────────────────────────────────────────────────────────────
// LastPass CSV columns: url,username,password,totp,extra,name,grouping,fav

func parseLastPass(r io.Reader) ([]Record, error) {
	reader := csv.NewReader(r)
	reader.LazyQuotes = true
	rows, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("parse lastpass CSV: %w", err)
	}
	if len(rows) < 2 {
		return nil, fmt.Errorf("lastpass CSV has no data rows")
	}

	// Build column index from header.
	header := rows[0]
	col := func(name string) int {
		for i, h := range header {
			if strings.EqualFold(strings.TrimSpace(h), name) {
				return i
			}
		}
		return -1
	}

	urlIdx := col("url")
	userIdx := col("username")
	passIdx := col("password")
	totpIdx := col("totp")
	notesIdx := col("extra")
	nameIdx := col("name")
	groupIdx := col("grouping")

	var records []Record
	for _, row := range rows[1:] {
		get := func(idx int) string {
			if idx < 0 || idx >= len(row) {
				return ""
			}
			return strings.TrimSpace(row[idx])
		}

		name := get(nameIdx)
		if name == "" {
			name = get(urlIdx)
		}
		if name == "" {
			continue
		}

		var tags []string
		if g := get(groupIdx); g != "" {
			tags = append(tags, sanitiseName(g))
		}

		records = append(records, Record{
			Name: sanitiseName(name),
			Payload: &entry.Payload{
				Username:   get(userIdx),
				Password:   get(passIdx),
				URL:        get(urlIdx),
				TOTPSecret: get(totpIdx),
				Notes:      get(notesIdx),
			},
			Tags: tags,
		})
	}
	return records, nil
}

// ── Generic CSV ──────────────────────────────────────────────────────────────
// Columns: name,username,password,url,notes  (header required)

func parseGenericCSV(r io.Reader) ([]Record, error) {
	reader := csv.NewReader(r)
	rows, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("parse CSV: %w", err)
	}
	if len(rows) < 2 {
		return nil, fmt.Errorf("CSV has no data rows")
	}

	var records []Record
	for _, row := range rows[1:] {
		get := func(idx int) string {
			if idx >= len(row) {
				return ""
			}
			return strings.TrimSpace(row[idx])
		}
		records = append(records, Record{
			Name: sanitiseName(get(0)),
			Payload: &entry.Payload{
				Username: get(1),
				Password: get(2),
				URL:      get(3),
				Notes:    get(4),
			},
		})
	}
	return records, nil
}

// sanitiseName makes a credential name safe for use as a filename.
// Spaces → hyphens, strips special chars, lowercases.
func sanitiseName(s string) string {
	s = strings.TrimSpace(s)
	var b strings.Builder
	for _, c := range strings.ToLower(s) {
		switch {
		case (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_':
			b.WriteRune(c)
		case c == ' ' || c == '.' || c == '/':
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}
