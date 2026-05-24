package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/spf13/cobra"
)

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Start the MCP server for AI agent integration",
	Long: `Launches a read-only MCP (Model Context Protocol) server over stdio.

AI agents connect via Claude Desktop, Cursor, or any MCP-compatible client.
The server exposes credentials that the configured identity is authorised to
decrypt. Write operations (add, grant, revoke) are intentionally not exposed —
manage access through the CLI.

SECURITY NOTE: Prompt injection can trick an agent into calling get_credential
and including the result in visible output. Instruct your agent to use
credentials directly (e.g. as HTTP headers) without echoing them.

Required environment:
  AMAN_PASSPHRASE=<passphrase>   private key passphrase (no interactive prompt in MCP mode)
  AMAN_IDENTITY=<name>           your member name (or use --identity flag)

Example ~/.config/claude/claude_desktop_config.json entry:

  {
    "mcpServers": {
      "aman": {
        "command": "/usr/local/bin/aman",
        "args": ["mcp", "--vault", "/path/to/team-vault"],
        "env": {
          "AMAN_IDENTITY": "alice",
          "AMAN_PASSPHRASE": "your-passphrase"
        }
      }
    }
  }`,
	RunE: runMCP,
}

func init() {
	rootCmd.AddCommand(mcpCmd)
}

func runMCP(_ *cobra.Command, _ []string) error {
	identity, err := identityName()
	if err != nil {
		return fmt.Errorf("MCP mode requires an identity: %w\n  set AMAN_IDENTITY=<name> or use --identity", err)
	}

	// Refuse to start without AMAN_PASSPHRASE — interactive prompts are impossible over stdio.
	if os.Getenv("AMAN_PASSPHRASE") == "" {
		return fmt.Errorf("AMAN_PASSPHRASE environment variable is required for MCP mode (no interactive prompt available)")
	}

	v, err := openVault()
	if err != nil {
		return fmt.Errorf("open vault: %w", err)
	}

	// Load keypair once at startup; AMAN_PASSPHRASE is already set so this is non-interactive.
	kp, err := loadKeyPair(identity)
	if err != nil {
		return fmt.Errorf("load keypair for %q: %w", identity, err)
	}

	s := server.NewMCPServer(
		"aman — PQC credential store",
		"1.0.0",
		server.WithLogging(),
	)

	// ── list_credentials ──────────────────────────────────────────────────────

	s.AddTool(mcp.NewTool("list_credentials",
		mcp.WithDescription("List credential names this identity can access. Returns names, tags, "+
			"recipients, and last-updated dates. Never returns credential values."),
		mcp.WithBoolean("all", mcp.Description("Include entries this identity cannot decrypt (default: false)")),
		mcp.WithString("tag", mcp.Description("Filter by tag")),
	), func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := mcpArgs(req)
		showAll := mcpBool(args, "all", false)
		tagFilter := mcpString(args, "tag", "")

		items, err := v.List(identity)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		type credSummary struct {
			Name       string   `json:"name"`
			Accessible bool     `json:"accessible"`
			Recipients []string `json:"recipients"`
			Tags       []string `json:"tags,omitempty"`
			UpdatedAt  string   `json:"updated_at"`
		}

		var creds []credSummary
		for _, li := range items {
			if !showAll && !li.CanDecrypt {
				continue
			}
			if tagFilter != "" && !hasTag(li.Tags, tagFilter) {
				continue
			}
			creds = append(creds, credSummary{
				Name:       li.Name,
				Accessible: li.CanDecrypt,
				Recipients: li.Recipients,
				Tags:       li.Tags,
				UpdatedAt:  li.UpdatedAt.Format("2006-01-02"),
			})
		}

		out, _ := json.Marshal(map[string]any{
			"identity":    identity,
			"vault":       v.Cfg.Name,
			"credentials": creds,
			"count":       len(creds),
		})
		return mcp.NewToolResultText(string(out)), nil
	})

	// ── get_credential ────────────────────────────────────────────────────────

	s.AddTool(mcp.NewTool("get_credential",
		mcp.WithDescription("Decrypt a credential and return the requested field.\n\n"+
			"⚠ SECURITY: use the returned value directly in your task (e.g. as an HTTP header or "+
			"environment variable). Do NOT include it in any text visible to the user — this prevents "+
			"credential leakage via AI output."),
		mcp.WithString("name", mcp.Required(), mcp.Description("Credential name (from list_credentials)")),
		mcp.WithString("field", mcp.Description("Field to retrieve: password (default), user, url, notes")),
	), func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := mcpArgs(req)
		name := mcpString(args, "name", "")
		field := mcpString(args, "field", "password")

		if name == "" {
			return mcp.NewToolResultError("name is required"), nil
		}

		payload, err := v.Get(name, identity, kp)
		if err != nil {
			// Deliberately vague — don't leak whether the entry exists.
			return mcp.NewToolResultError("access denied or credential not found"), nil
		}

		var value string
		switch field {
		case "password", "pass", "":
			value = payload.Password
		case "user", "username":
			value = payload.Username
		case "url":
			value = payload.URL
		case "notes":
			value = payload.Notes
		default:
			if cv, ok := payload.Fields[field]; ok {
				value = cv
			} else {
				return mcp.NewToolResultError(
					fmt.Sprintf("unknown field %q — valid: password, user, url, notes", field),
				), nil
			}
		}

		if value == "" {
			return mcp.NewToolResultError(
				fmt.Sprintf("field %q is empty for %q", field, name),
			), nil
		}

		out, _ := json.Marshal(map[string]any{
			"name":     name,
			"field":    field,
			"value":    value,
			"_warning": "use this value directly — do not include in visible output",
		})
		return mcp.NewToolResultText(string(out)), nil
	})

	// ── check_access ──────────────────────────────────────────────────────────

	s.AddTool(mcp.NewTool("check_access",
		mcp.WithDescription("Check whether the configured identity can decrypt a specific credential. "+
			"Use this before get_credential to handle access-denied gracefully."),
		mcp.WithString("name", mcp.Required(), mcp.Description("Credential name to check")),
	), func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		name := mcpString(mcpArgs(req), "name", "")
		if name == "" {
			return mcp.NewToolResultError("name is required"), nil
		}

		items, err := v.List(identity)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		for _, li := range items {
			if li.Name == name {
				out, _ := json.Marshal(map[string]any{
					"name":       name,
					"accessible": li.CanDecrypt,
					"recipients": li.Recipients,
				})
				return mcp.NewToolResultText(string(out)), nil
			}
		}

		out, _ := json.Marshal(map[string]any{
			"name":       name,
			"accessible": false,
			"error":      "credential not found",
		})
		return mcp.NewToolResultText(string(out)), nil
	})

	return server.ServeStdio(s)
}

// ── helpers ───────────────────────────────────────────────────────────────────

func mcpArgs(req mcp.CallToolRequest) map[string]any {
	args, _ := req.Params.Arguments.(map[string]any)
	return args
}

func mcpString(args map[string]any, key, def string) string {
	if v, ok := args[key].(string); ok {
		return v
	}
	return def
}

func mcpBool(args map[string]any, key string, def bool) bool {
	if v, ok := args[key].(bool); ok {
		return v
	}
	return def
}
