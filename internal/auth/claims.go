package auth

import "github.com/golang-jwt/jwt/v5"

const HumanTokenType = "human"

type Claims struct {
	WorkspaceID string   `json:"ws"`
	Type        string   `json:"typ"`
	MemberID    string   `json:"mem,omitempty"`
	OnBehalfOf  string   `json:"obo,omitempty"`
	Actor       string   `json:"act,omitempty"`
	AgentID     string   `json:"agent,omitempty"`
	RunID       string   `json:"run_id,omitempty"`
	Context     string   `json:"ctx,omitempty"`
	Scopes      []string `json:"scope"`

	jwt.RegisteredClaims
}
