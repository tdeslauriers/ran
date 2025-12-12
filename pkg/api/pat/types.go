package pat

// Pat is the output model representing a personal access token (PAT) --> it is never stored.
type Pat struct {
	Client    string `json:"client,omitempty"` // client name: convenience field
	Token     string `json:"token,omitempty"`  // the actual token is only returned once, upon creation
	CreatedAt string `json:"created_at"`
	Active    bool   `json:"active"`
	Revoked   bool   `json:"revoked"`
	Expired   bool   `json:"expired"`
}
