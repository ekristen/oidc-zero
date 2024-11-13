package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"time"

	"golang.org/x/text/language"

	"github.com/go-chi/chi/v5"
	"github.com/sirupsen/logrus"
	"github.com/zitadel/logging"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/ekristen/oidc-zero/pkg/config"
	"github.com/ekristen/oidc-zero/pkg/storage"
)

const (
	pathLoggedOut = "/logged-out"
)

type Storage interface {
	op.Storage
	authenticate
}

type Options struct {
	Port   int
	Config *config.Config
	Log    *logrus.Entry
}

func exchangeCodeForToken(code string) (string, error) {
	// Replace these with your OIDC provider's details
	tokenEndpoint := "http://localhost:4242/oauth/token"
	clientID := "nomad"
	clientSecret := "nomad"
	redirectURI := "http://localhost:4242/callback"

	// Prepare the request body
	requestBody, err := json.Marshal(map[string]string{
		"grant_type":    "authorization_code",
		"code":          code,
		"redirect_uri":  redirectURI,
		"client_id":     clientID,
		"client_secret": clientSecret,
	})
	if err != nil {
		return "", fmt.Errorf("error marshalling request body: %v", err)
	}

	// Create the request
	req, err := http.NewRequest("POST", tokenEndpoint, bytes.NewBuffer(requestBody))
	if err != nil {
		return "", fmt.Errorf("error creating request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("error sending request to token endpoint: %v", err)
	}
	defer resp.Body.Close()

	// Check the response status
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("received non-200 response from token endpoint: %d", resp.StatusCode)
	}

	// Decode the response body to extract the token
	var tokenResponse struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return "", fmt.Errorf("error decoding token response: %v", err)
	}

	return tokenResponse.AccessToken, nil
}

func SetupServer(issuer string, storage Storage, logger *slog.Logger, wrapServer bool, extraOptions ...op.Option) chi.Router {
	// the OpenID Provider requires a 32-byte key for (token) encryption
	// be sure to create a proper crypto random key and manage it securely!
	key := sha256.Sum256([]byte("thisisaverysecretthing"))

	router := chi.NewRouter()
	router.Use(logging.Middleware(
		logging.WithLogger(logger),
	))

	router.HandleFunc("/callback", func(w http.ResponseWriter, req *http.Request) {
		// Step 1: Extract the code parameter from the request
		code := req.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "Code not found", http.StatusBadRequest)
			return
		}

		// Step 2 & 3: Prepare and perform the token exchange
		token, err := exchangeCodeForToken(code)
		if err != nil {
			http.Error(w, "Failed to exchange code for token: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Step 4: Handle the JWT token (example: return it to the client)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(fmt.Sprintf(`{"token": "%s"}`, token)))
	})

	// for simplicity, we provide a very small default page for users who have signed out
	router.HandleFunc(pathLoggedOut, func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte("signed out successfully"))
		// no need to check/log error, this will be handled by the middleware.
	})

	// creation of the OpenIDProvider with the just created in-memory Storage
	provider, err := newOP(storage, issuer, key, logger, extraOptions...)
	if err != nil {
		log.Fatal(err)
	}

	//the provider will only take care of the OpenID Protocol, so there must be some sort of UI for the Login process
	//for the simplicity of the example this means a simple page with username and password field
	//be sure to provide an IssuerInterceptor with the IssuerFromRequest from the OP so the Login can select / and pass it to the storage
	l := NewLogin(storage, op.AuthCallbackURL(provider), op.NewIssuerInterceptor(provider.IssuerFromRequest))

	// regardless of how many pages / steps there are in the process, the UI must be registered in the router,
	// so we will direct all calls to /Login to the Login UI
	router.Mount("/login/", http.StripPrefix("/login", l.router))

	router.HandleFunc("/css/{file}", func(w http.ResponseWriter, r *http.Request) {
		data, err := files.ReadFile(fmt.Sprintf("files/%s", chi.URLParam(r, "file")))
		if err != nil {
			http.Error(w, "file not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/css")
		w.Write(data)
	})

	handler := http.Handler(provider)
	if wrapServer {
		handler = op.RegisterLegacyServer(op.NewLegacyServer(provider, *op.DefaultEndpoints), op.AuthorizeCallbackHandler(provider))
	}

	// we register the http handler of the OP on the root, so that the discovery endpoint (/.well-known/openid-configuration)
	// is served on the correct path
	//
	// if your issuer ends with a path (e.g. http://localhost:9998/custom/path/),
	// then you would have to set the path prefix (/custom/path/)
	router.Mount("/", handler)

	return router
}

// newOP will create an OpenID Provider for localhost on a specified port with a given encryption key
// and a predefined default logout uri
// it will enable all options (see descriptions)
func newOP(storage op.Storage, issuer string, key [32]byte, logger *slog.Logger, extraOptions ...op.Option) (op.OpenIDProvider, error) {
	config := &op.Config{
		CryptoKey: key,

		// will be used if the end_session endpoint is called without a post_logout_redirect_uri
		DefaultLogoutRedirectURI: pathLoggedOut,

		// enables code_challenge_method S256 for PKCE (and therefore PKCE in general)
		CodeMethodS256: true,

		// enables additional client_id/client_secret authentication by form post (not only HTTP Basic Auth)
		AuthMethodPost: true,

		// enables additional authentication by using private_key_jwt
		AuthMethodPrivateKeyJWT: true,

		// enables refresh_token grant use
		GrantTypeRefreshToken: true,

		// enables use of the `request` Object parameter
		RequestObjectSupported: true,

		// this example has only static texts (in English), so we'll set the here accordingly
		SupportedUILocales: []language.Tag{language.English},

		DeviceAuthorization: op.DeviceAuthorizationConfig{
			Lifetime:     5 * time.Minute,
			PollInterval: 5 * time.Second,
			UserFormPath: "/device",
			UserCode:     op.UserCodeBase20,
		},
	}

	handler, err := op.NewOpenIDProvider(issuer, config, storage,
		append([]op.Option{
			//we must explicitly allow the use of the http issuer
			op.WithAllowInsecure(),
			// Pass our logger to the OP
			op.WithLogger(logger.WithGroup("op")),
		}, extraOptions...)...,
	)
	if err != nil {
		return nil, err
	}
	return handler, nil
}

func RunServer(ctx context.Context, opts *Options) error {
	if opts.Log == nil {
		opts.Log = logrus.WithField("component", "api-server")
	} else {
		opts.Log = opts.Log.WithField("component", "api-server")
	}

	port := opts.Port
	issuer := fmt.Sprintf("http://localhost:%d/", port)

	for _, client := range opts.Config.Clients {
		if client.Type == "web" || client.Type == "" {
			storage.RegisterClients(
				storage.WebClient(client.ID, client.Secret, client.RedirectURIs...),
			)
		}
	}

	// the OpenIDProvider interface needs a Storage interface handling various checks and state manipulations
	// this might be the layer for accessing your database
	// in this example it will be handled in-memory
	str := storage.NewStorage(storage.NewUserStore(issuer, opts.Config.Users))

	logger := slog.New(
		slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			AddSource: true,
			Level:     slog.LevelDebug,
		}),
	)
	router := SetupServer(issuer, str, logger, true)

	router.HandleFunc("/", RootHandler)

	// Below this point is where the server is started and graceful shutdown occurs.

	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", opts.Port),
		Handler:           router,
		ReadTimeout:       1 * time.Second,
		WriteTimeout:      1 * time.Second,
		IdleTimeout:       30 * time.Second,
		ReadHeaderTimeout: 2 * time.Second,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			opts.Log.Fatalf("listen: %s\n", err)
		}
	}()
	opts.Log.WithField("port", opts.Port).Info("starting api server")

	<-ctx.Done()

	opts.Log.Info("shutting down api server")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		opts.Log.WithError(err).Error("unable to shutdown the api server gracefully")
		return err
	}

	return nil
}
