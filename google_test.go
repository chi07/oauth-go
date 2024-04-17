package oauth

import (
	"strings"
	"testing"
)

func TestNewGoogleAuth(t *testing.T) {
	clientID := "your-client-id"
	clientSecret := "your-client-secret"
	redirectURL := "http://localhost:8080/callback"

	ga := NewGoogleAuth(clientID, clientSecret, redirectURL)

	if ga.ClientID != clientID {
		t.Errorf("Expected ClientID %s, got %s", clientID, ga.ClientID)
	}
	if ga.ClientSecret != clientSecret {
		t.Errorf("Expected ClientSecret %s, got %s", clientSecret, ga.ClientSecret)
	}
	if ga.RedirectURL != redirectURL {
		t.Errorf("Expected RedirectURL %s, got %s", redirectURL, ga.RedirectURL)
	}
}

func TestGetAuthGoogleLink(t *testing.T) {
	clientID := "your-client-id"
	clientSecret := "your-client-secret"
	redirectURL := "http://localhost:8080/callback"

	ga := NewGoogleAuth(clientID, clientSecret, redirectURL)
	link := ga.GetAuthGoogleLink()

	if !strings.Contains(link, "https://accounts.google.com/o/oauth2/auth") {
		t.Errorf("Expected link to contain 'https://accounts.google.com/o/oauth2/auth', got %s", link)
	}
	if !strings.Contains(link, "client_id="+clientID) {
		t.Errorf("Expected link to contain 'client_id=%s', got %s", clientID, link)
	}
	if !strings.Contains(link, "scope=profile+email") {
		t.Errorf("Expected link to contain 'scope=profile+email', got %s", link)
	}
}
