package secretcheck

import (
	"context"
	"net/http"
	"strings"
	"time"
)

type SecretType string

const (
	SecretAWSKey  SecretType = "aws_access_key"
	SecretGitHub  SecretType = "github_token"
	SecretStripe  SecretType = "stripe_key"
	SecretSlack   SecretType = "slack_token"
	SecretGeneric SecretType = "generic_api_key"
)

type SecretValidity struct {
	SecretType SecretType `json:"secret_type"`
	IsValid    bool       `json:"is_valid"`
	StatusCode int        `json:"status_code"`
	CheckedAt  time.Time  `json:"checked_at"`
	Endpoint   string     `json:"endpoint"`
	Error      string     `json:"error,omitempty"`
}

type Checker struct {
	http *http.Client
}

func NewChecker() *Checker {
	return &Checker{
		http: &http.Client{
			Timeout: 8 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func DetectType(value string) SecretType {
	switch {
	case strings.HasPrefix(value, "AKIA") || strings.HasPrefix(value, "ASIA"):
		return SecretAWSKey
	case strings.HasPrefix(value, "ghp_") || strings.HasPrefix(value, "github_pat_"):
		return SecretGitHub
	case strings.HasPrefix(value, "sk_live_") || strings.HasPrefix(value, "sk_test_"):
		return SecretStripe
	case strings.HasPrefix(value, "xoxb-") || strings.HasPrefix(value, "xoxp-"):
		return SecretSlack
	default:
		return SecretGeneric
	}
}

func (c *Checker) Check(ctx context.Context, secretType SecretType, value string) *SecretValidity {
	result := &SecretValidity{SecretType: secretType, CheckedAt: time.Now()}
	switch secretType {
	case SecretAWSKey:
		c.checkAWS(ctx, value, result)
	case SecretGitHub:
		c.checkGitHub(ctx, value, result)
	case SecretStripe:
		c.checkStripe(ctx, value, result)
	case SecretSlack:
		c.checkSlack(ctx, value, result)
	default:
		result.Error = "unsupported secret type"
	}
	return result
}

func (c *Checker) checkGitHub(ctx context.Context, token string, r *SecretValidity) {
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user", nil)
	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("User-Agent", "VSP/1.0")
	resp, err := c.http.Do(req)
	if err != nil { r.Error = err.Error(); return }
	defer resp.Body.Close()
	r.StatusCode = resp.StatusCode
	r.Endpoint = "https://api.github.com/user"
	r.IsValid = resp.StatusCode == 200
}

func (c *Checker) checkStripe(ctx context.Context, key string, r *SecretValidity) {
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://api.stripe.com/v1/charges?limit=1", nil)
	req.SetBasicAuth(key, "")
	resp, err := c.http.Do(req)
	if err != nil { r.Error = err.Error(); return }
	defer resp.Body.Close()
	r.StatusCode = resp.StatusCode
	r.Endpoint = "https://api.stripe.com/v1/charges"
	r.IsValid = resp.StatusCode == 200
}

func (c *Checker) checkSlack(ctx context.Context, token string, r *SecretValidity) {
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://slack.com/api/auth.test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.http.Do(req)
	if err != nil { r.Error = err.Error(); return }
	defer resp.Body.Close()
	r.StatusCode = resp.StatusCode
	r.Endpoint = "https://slack.com/api/auth.test"
	r.IsValid = resp.StatusCode == 200
}

func (c *Checker) checkAWS(ctx context.Context, key string, r *SecretValidity) {
	req, _ := http.NewRequestWithContext(ctx, "GET",
		"https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15", nil)
	resp, err := c.http.Do(req)
	if err != nil { r.Error = err.Error(); return }
	defer resp.Body.Close()
	r.StatusCode = resp.StatusCode
	r.Endpoint = "https://sts.amazonaws.com"
	r.IsValid = resp.StatusCode == 400
}
