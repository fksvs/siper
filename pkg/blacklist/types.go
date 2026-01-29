package blacklist

type Rule struct {
	ID        string `json:"id"`
	Cidr      string `json:"cidr"`
	Family    string `json:"family"`
	Enabled   bool   `json:"enabled"`
	Source    string `json:"source"`
	Comment   string `json:"comment"`
	CreatedAt string `json:"created_at"`
}

type Blacklist struct {
	Version   string `json:"version"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
	Rules     []Rule `json:"rules"`
}
