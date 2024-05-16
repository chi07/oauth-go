package oauth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/oauth2"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/rs/zerolog/log"
)

type GoogleOauthToken struct {
	AccessToken string
	IDToken     string
}

type GoogleAuth struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	HTTPClient   *http.Client
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
		HTTPClient: &http.Client{
			Timeout: time.Second * 30,
		},
	}
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
		log.Error().Err(err).Msg("could not create request to Google OAuth API")
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := ga.HTTPClient.Do(req)
	if err != nil {
		log.Error().Err(err).Msg("could not make request to Google OAuth API")
		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		log.Error().Err(err).Msg("could not retrieve token from Google OAuth API")
		return nil, errors.New("could not retrieve token from Google OAuth API")
	}

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	var GoogleOauthTokenRes map[string]interface{}

	if err = json.Unmarshal(resBody, &GoogleOauthTokenRes); err != nil {
		log.Error().Err(err).Msg("could not unmarshal response from Google OAuth API")
		return nil, err
	}

	accessToken, ok := GoogleOauthTokenRes["access_token"].(string)
	if !ok {
		log.Error().Msg("could not retrieve access token from Google OAuth API response")
		return nil, errors.New("could not retrieve access token from Google OAuth API response")
	}

	tokenID, ok := GoogleOauthTokenRes["id_token"].(string)
	if !ok {
		log.Error().Msg("could not retrieve id_token from Google OAuth API response")
		return nil, errors.New("could not retrieve id_token from Google OAuth API response")
	}

	tokenBody := &GoogleOauthToken{
		AccessToken: accessToken,
		IDToken:     tokenID,
	}

	return tokenBody, nil
}

func (ga *GoogleAuth) GetGoogleUser(accessToken string, tokenID string) (*GoogleUser, error) {
	infoURL := fmt.Sprintf("https://www.googleapis.com/oauth2/v1/userinfo?alt=json&access_token=%s", accessToken)

	req, err := http.NewRequest("GET", infoURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tokenID))

	res, err := ga.HTTPClient.Do(req)
	if err != nil {
		log.Error().Err(err).Msg("could not make request to Google User Info API")
		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		return nil, errors.New("could not retrieve user from Google User Info API")
	}

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	var GoogleUserRes map[string]interface{}

	if err := json.Unmarshal(resBody, &GoogleUserRes); err != nil {
		log.Error().Err(err).Msg("could not unmarshal response from Google User Info API")
		return nil, err
	}

	userBody := &GoogleUser{
		ID:            GoogleUserRes["id"].(string),
		Email:         GoogleUserRes["email"].(string),
		VerifiedEmail: GoogleUserRes["verified_email"].(bool),
		Name:          GoogleUserRes["name"].(string),
		GivenName:     GoogleUserRes["given_name"].(string),
		FamilyName:    GoogleUserRes["family_name"].(string),
		Picture:       GoogleUserRes["picture"].(string),
	}

	return userBody, nil
}
