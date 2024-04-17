package oauth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/oauth2"
)

type GoogleOauthToken struct {
	AccessToken string
	IDToken     string
}

type GoogleAuth struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
}

type GoogleUser struct {
	ID            string
	Email         string
	VerifiedEmail bool
	Name          string
	GivenName     string
	FamilyName    string
	Picture       string
	Locale        string
}

func NewGoogleAuth(clientID, clientSecret, redirectURL string) *GoogleAuth {
	return &GoogleAuth{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
	}
}

func (ga *GoogleAuth) GetGoogleOauthToken(code string) (*GoogleOauthToken, error) {
	const rootURL = "https://oauth2.googleapis.com/token"

	values := url.Values{}
	values.Add("grant_type", "authorization_code")
	values.Add("code", code)
	values.Add("client_id", ga.ClientID)
	values.Add("client_secret", ga.ClientSecret)
	values.Add("redirect_uri", ga.RedirectURL)

	query := values.Encode()
	req, err := http.NewRequest("POST", rootURL, bytes.NewBufferString(query))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := http.Client{
		Timeout: time.Second * 30,
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		return nil, errors.New("could not retrieve token")
	}

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	var GoogleOauthTokenRes map[string]interface{}

	if err := json.Unmarshal(resBody, &GoogleOauthTokenRes); err != nil {
		return nil, err
	}

	tokenBody := &GoogleOauthToken{
		AccessToken: GoogleOauthTokenRes["access_token"].(string),
		IDToken:     GoogleOauthTokenRes["id_token"].(string),
	}

	return tokenBody, nil
}

func (ga *GoogleAuth) GetGoogleUser(accessToken string, tokenID string) (*GoogleUser, error) {
	rootUrl := fmt.Sprintf("https://www.googleapis.com/oauth2/v1/userinfo?alt=json&access_token=%s", accessToken)

	req, err := http.NewRequest("GET", rootUrl, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tokenID))

	client := http.Client{
		Timeout: time.Second * 30,
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		return nil, errors.New("could not retrieve user")
	}

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	var GoogleUserRes map[string]interface{}

	if err := json.Unmarshal(resBody, &GoogleUserRes); err != nil {
		return nil, err
	}

	userBody := &GoogleUser{
		ID:            GoogleUserRes["id"].(string),
		Email:         GoogleUserRes["email"].(string),
		VerifiedEmail: GoogleUserRes["verified_email"].(bool),
		Name:          GoogleUserRes["name"].(string),
		GivenName:     GoogleUserRes["given_name"].(string),
		Picture:       GoogleUserRes["picture"].(string),
		Locale:        GoogleUserRes["locale"].(string),
	}

	return userBody, nil
}

func (ga *GoogleAuth) GetAuthGoogleLink() string {
	oauthConfig := oauth2.Config{
		ClientID:     ga.ClientID,
		ClientSecret: ga.ClientSecret,
		RedirectURL:  ga.RedirectURL,
		Scopes:       []string{"profile", "email"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://accounts.google.com/o/oauth2/auth",
			TokenURL: "https://accounts.google.com/o/oauth2/token",
		},
	}

	return oauthConfig.AuthCodeURL("state")
}
