package main

import (
	"log"
	"net/http"
	"os"
	"time"
	"math/rand"
	_ "github.com/motemen/go-loghttp/global"

	oidc "github.com/coreos/go-oidc"
	cv "github.com/nirasan/go-oauth-pkce-code-verifier"

	"golang.org/x/net/context"
	"golang.org/x/oauth2"
)

var (
	clientID       = os.Getenv("OAUTH2_CLIENT_ID")
	clientSecret   = os.Getenv("OAUTH2_CLIENT_SECRET")
	oauth2Provider = os.Getenv("OAUTH2_PROVIDER")
	redirectURL    = os.Getenv("OAUTH2_REDIRECT_URL")

	mobileClientID = os.Getenv("OAUTH2_MOBILE_CLIENT_ID")
	mobileURL      = os.Getenv("OAUTH2_MOBILE_URL")

	port           = os.Getenv("PORT")

	state string
	config, mobileConfig oauth2.Config
	provider *oidc.Provider

	seededRand *rand.Rand = rand.New(rand.NewSource(time.Now().UnixNano()))
	codeVerifier, codeChallenge string
)

func main() {
	ctx := context.Background()

	var err error
	provider, err = oidc.NewProvider(ctx, oauth2Provider)
	if err != nil {
		log.Fatal(err)
	}

	// config for Web app 
	config = oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  redirectURL,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email", "offline_access"},
	}

	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/dashboard", dashboardHandler)


	// config for mobile app (PKCE)
	mobileConfig = oauth2.Config{
		ClientID:     mobileClientID,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  mobileURL,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email", "offline_access"},
	}
	http.HandleFunc("/mobile/login", mobileLoginHandler)
	http.HandleFunc("/mobile/dashboard", mobileDashboardHandler)

        log.Printf("listening on http://%s/", "localhost:"+port)
        log.Fatal(http.ListenAndServe("localhost:"+port, nil))
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	state = randomString(16)
	url := config.AuthCodeURL(state,oauth2.AccessTypeOffline)
	log.Print("AuthCode URL = ", url)
	http.Redirect(w, r, url, http.StatusFound)
}

func mobileLoginHandler(w http.ResponseWriter, r *http.Request) {
	state = randomString(16)
	codeVerifier, codeChallenge = getPKCEPair()
	url := mobileConfig.AuthCodeURL( state, oauth2.AccessTypeOffline) +
		"&code_challenge_method=S256" +
		"&code_challenge="+codeChallenge
	log.Print("Mobile AuthCodeURL = ", url)
	http.Redirect(w, r, url, http.StatusFound)
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {

	if r.URL.Query().Get("state") != state {
		http.Error(w, "state did not match", http.StatusBadRequest)
		return
	}

	ctx := context.Background()
	// Exchange the code in the URL string for a token
	oauth2Token, err := config.Exchange(ctx, r.URL.Query().Get("code"))
	if err != nil {
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)
		return
	}

	// Verify the token
	verifier := provider.Verifier(&oidc.Config{
	   ClientID: clientID,
	})

	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	log.Print("Access Token = ", oauth2Token.AccessToken)
	log.Print("ID Token Subject = ", idToken.Subject)
	log.Print("Refresh Token = ", oauth2Token.RefreshToken)

	// Extract custom claims
	var claims struct {
	    Email    string `json:"email"`
	    Name string `json:"name"`

	}
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	        return 
	}

	log.Print ("Logged in ", claims.Email)
	greet := "Welcome to Georgia Pinball, "+claims.Name+"\n\n"
	greet += "You're currently logged in as "+claims.Email+"\n\n"
	greet += "You'll be logged out "+oauth2Token.Expiry.Format(time.UnixDate)+"\n\n"
	w.Write([]byte(greet))

	// Now get User Info and display it
	userInfo, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(oauth2Token))
	if err != nil {
		http.Error(w, "Failed to get userinfo: "+err.Error(), http.StatusInternalServerError)
		return
	}
	var uiClaims struct {
            Email    string `json:"email"`
            Name     string `json:"name"`
	    Nickname string `json:"nickname"`
	    TimeZone string `json:"zoneinfo"`
	    Locale   string `json:"locale"`
	}
	if err := userInfo.Claims(&uiClaims); err != nil {
		log.Print("Error getting UserInfo Claims")
	}
	w.Write([]byte("User Info (Profile):"))
        w.Write([]byte("\n   name:     " + uiClaims.Name))
	w.Write([]byte("\n   email:    " + uiClaims.Email))
	w.Write([]byte("\n   nickname: " + uiClaims.Nickname))
	w.Write([]byte("\n   timezone: " + uiClaims.TimeZone))
	w.Write([]byte("\n   locale:   " + uiClaims.Locale))
}

func mobileDashboardHandler(w http.ResponseWriter, r *http.Request) {

	if r.URL.Query().Get("state") != state {
		http.Error(w, "state did not match", http.StatusBadRequest)
		return
	}
	ctx := context.Background()
	// Exchange the code in the URL string for a token
	code := r.URL.Query().Get("code")
	oauth2Token, err := mobileConfig.Exchange(ctx, code,
		oauth2.SetAuthURLParam("code_verifier", codeVerifier))
	if err != nil {
		log.Print(err.Error())
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)
		return
	}
	// Verify the token
	verifier := provider.Verifier(&oidc.Config{
		ClientID: mobileClientID,
	})

	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	log.Print("Access Token = ", oauth2Token.AccessToken)
	log.Print("ID Token Subject = ", idToken.Subject)
	log.Print("Refresh Token = ", oauth2Token.RefreshToken)

	// Extract custom claims

	var claims struct {
		Email    string `json:"email"`
		Name string `json:"name"`
	}
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Print ("Logged in ", claims.Email) 
	greet := "Welcome to Georgia Pinball's mobile site, "+claims.Name+"\n\n"
	greet += "You're currently logged in as "+claims.Email+"\n\n"
	greet += "You'll be logged out "+oauth2Token.Expiry.Format(time.UnixDate)+"\n\n"
	w.Write([]byte(greet))

	// Now get User Info and display it
	userInfo, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(oauth2Token)) 
	if err != nil {
		http.Error(w, "Failed to get userinfo: "+err.Error(), http.StatusInternalServerError)
		return
	}
	var uiClaims struct {
		Email    string `json:"email"`
		Name     string `json:"name"`
		Nickname string `json:"nickname"`
		TimeZone string `json:"zoneinfo"`
		Locale   string `json:"locale"`
	}
	if err := userInfo.Claims(&uiClaims); err != nil {
		log.Print("Error getting UserInfo Claims")
	}
	w.Write([]byte("User Info (Profile):"))
	w.Write([]byte("\n   name:     " + uiClaims.Name))
	w.Write([]byte("\n   email:    " + uiClaims.Email))
	w.Write([]byte("\n   nickname: " + uiClaims.Nickname))
	w.Write([]byte("\n   timezone: " + uiClaims.TimeZone))
	w.Write([]byte("\n   locale:   " + uiClaims.Locale))
}

const charset = "abcdefghijklmnopqrstuvwxyz" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func randomString (length int) string {
	b := make([]byte, length)
	for i := range b {
	   b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

func randomSlice (length int) []byte {
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return b
}

// see https://tools.ietf.org/html/rfc7636#section-4.1
func getPKCEPair() (string, string) {

	var CodeVerifier, _ = cv.CreateCodeVerifier()
	codeVerifier = CodeVerifier.String()
	codeChallenge = CodeVerifier.CodeChallengeS256()

	log.Print("CodeVerifier = ", codeVerifier)
	log.Print("   Length = ", len(codeVerifier))
	log.Print("CodeChallenge = ", codeChallenge)

	return codeVerifier, codeChallenge
} 
