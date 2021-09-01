package ably

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"encoding/base64"
)

var (
	errMissingKey          = errors.New("missing key")
	errInvalidKey          = errors.New("invalid key")
	errMissingTokenOpts    = errors.New("missing options for token authentication")
	errMismatchedKeys      = errors.New("mismatched keys")
	errUnsupportedType     = errors.New("unsupported Content-Type header in response from AuthURL")
	errMissingType         = errors.New("missing Content-Type header in response from AuthURL")
	errInvalidCallbackType = errors.New("invalid value type returned from AuthCallback")
	errInsecureBasicAuth   = errors.New("basic auth is not supported on insecure non-TLS connections")
	errWildcardClientID    = errors.New("provided ClientID must not be a wildcard")
	errClientIDMismatch    = errors.New("the received ClientID does not match the requested one")
)

const wildcardClientID = "*"

// Auth
type Auth struct {
	mtx      sync.Mutex
	method   int
	client   *REST
	params   *TokenParams // save params to use with token renewal
	host     string       // a host part of AuthURL
	clientID string       // clientID of the authenticated user or wildcard "*"

	// onExplicitAuthorize is the callback that Realtime sets to reauthorize with the
	// server when Authorize is explicitly called.
	onExplicitAuthorize func(context.Context, *TokenDetails)

	serverTimeOffset time.Duration

	// ServerTimeHandler when provided this will be used to query server time.
	serverTimeHandler func() (time.Time, error)
}

func newAuth(client *REST) (*Auth, error) {
	a := &Auth{
		client:              client,
		onExplicitAuthorize: func(context.Context, *TokenDetails) {},
	}
	authMethod, err := a.detectAuthMethod()
	if err != nil {
		return nil, err
	}
	a.method = authMethod
	if a.opts().AuthURL != "" {
		u, err := url.Parse(a.opts().AuthURL)
		if err != nil {
			return nil, newError(40003, err)
		}
		a.host = u.Host
	}
	if a.opts().Token != "" {
		a.opts().TokenDetails = newTokenDetails(a.opts().Token)
	}
	if a.opts().ClientID != "" {
		if a.opts().ClientID == wildcardClientID {
			// References RSA7c
			return nil, newError(ErrIncompatibleCredentials, errWildcardClientID)
		}
		// References RSC17, RSA7b1
		a.clientID = a.opts().ClientID
	}
	return a, nil
}

//detectAuthMethod - returns authBasic or authToken with valid checks
func (a *Auth) detectAuthMethod() (int, error) {
	opts := a.opts()
	// Checks for token auth (also check if external token auth ways provided)
	if opts.UseTokenAuth || opts.Token != "" || opts.TokenDetails != nil || opts.AuthCallback != nil || opts.AuthURL != "" {
		return authToken, nil
	}
	// checks for basic auth
	if err := checkIfKeyIsValid(&opts.authOptions); err != nil {
		return 0, err
	}
	if opts.NoTLS {
		return 0, newError(ErrInvalidUseOfBasicAuthOverNonTLSTransport, errInsecureBasicAuth)
	}
	return authBasic, nil
}

// ClientID
func (a *Auth) ClientID() string {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	if identifiable(a.clientID) {
		return a.clientID
	}
	return ""
}

func (a *Auth) updateClientID(clientID string) {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	//Spec RSA7b3, RSA7b4, RSA12a,RSA12b, RSA7b2,
	a.clientID = clientID
}

// CreateTokenRequest
func (a *Auth) CreateTokenRequest(tokenParams *TokenParams, authOpts ...AuthOption) (*TokenRequest, error) {
	a.mtx.Lock()
	defer a.mtx.Unlock()

	var o *authOptions
	if authOpts != nil {
		o = applyAuthOptionsWithDefaults(authOpts...)
	}
	return a.createTokenRequest(tokenParams, o)
}

func (a *Auth) createTokenRequest(tokenParams *TokenParams, authOpts *authOptions) (*TokenRequest, error) {
	if authOpts == nil {
		authOpts = &a.opts().authOptions
	}
	// Validate keyName/keySecret not empty
	if err := checkIfKeyIsValid(authOpts); err != nil {
		return nil, err
	}

	req := &TokenRequest{KeyName: authOpts.KeyName()}
	if tokenParams != nil {
		req.TokenParams = *tokenParams
	}
	// set defaults for empty fields of token request
	if req.Nonce == "" {
		req.Nonce = randomString(32)
	}
	if req.Capability == "" {
		req.Capability = `{"*":["*"]}`
	}
	if req.TTL == 0 {
		req.TTL = 60 * 60 * 1000
	}
	if req.ClientID == "" {
		req.ClientID = a.opts().ClientID
	}
	if req.Timestamp == 0 {
		ts, err := a.timestamp(context.Background(), authOpts.UseQueryTime)
		if err != nil {
			return nil, err
		}
		req.Timestamp = unixMilli(ts)
	}

	// sign the tokenRequest locally using keySecret
	req.sign([]byte(authOpts.KeySecret()))
	return req, nil
}

// RequestToken
func (a *Auth) RequestToken(ctx context.Context, params *TokenParams, opts ...AuthOption) (*TokenDetails, error) {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	var o *authOptions
	if opts != nil {
		o = applyAuthOptionsWithDefaults(opts...)
	}
	tok, _, err := a.requestToken(ctx, params, o)
	return tok, err
}

func (a *Auth) requestToken(ctx context.Context, tokenParams *TokenParams, authOpts *authOptions) (tok *TokenDetails, tokReqClientID string, err error) {
	// RSA10e - Use token/tokenDetails as is, if provided
	if authOpts != nil && authOpts.Token != "" {
		a.log().Verbose("Auth: found token in []AuthOption")
		return newTokenDetails(authOpts.Token), "", nil
	}
	if authOpts != nil && authOpts.TokenDetails != nil {
		a.log().Verbose("Auth: found TokenDetails in []AuthOption")
		return authOpts.TokenDetails, "", nil
	}

	if tokenParams == nil {
		tokenParams = a.opts().DefaultTokenParams
		// RSA7a4 - override defaultTokenParams clientID with a.ClientID if not empty
		if !empty(a.clientID) {
			tokenParams.ClientID = a.clientID
		}
	}
	// RSA10h, RSA7d - Use auth.ClientID for token auth
	if empty(tokenParams.ClientID) {
		tokenParams.ClientID = a.clientID
	}
	authOpts = a.mergeOpts(authOpts)
	var tokReq *TokenRequest
	switch {
	case authOpts.AuthCallback != nil:
		a.log().Verbose("Auth: found AuthCallback in []AuthOption")
		v, err := authOpts.AuthCallback(context.TODO(), *tokenParams)
		if err != nil {
			a.log().Error("Auth: failed calling opts.AuthCallback ", err)
			return nil, "", newError(ErrErrorFromClientTokenCallback, err)
		}

		// Simplify the switch below by removing the pointer-to-TokenLike cases.
		switch p := v.(type) {
		case *TokenRequest:
			v = *p
		case *TokenDetails:
			v = *p
		}

		switch v := v.(type) {
		case TokenRequest:
			tokReq = &v
			tokReqClientID = tokReq.ClientID
		case TokenDetails:
			return &v, "", nil
		case TokenString:
			return newTokenDetails(string(v)), "", nil
		default:
			panic(fmt.Errorf("unhandled TokenLike: %T", v))
		}
	case authOpts.AuthURL != "":
		a.log().Verbose("Auth: found AuthURL in []AuthOption")
		res, err := a.requestAuthURL(ctx, tokenParams, authOpts)
		if err != nil {
			a.log().Error("Auth: failed calling requesting token with AuthURL ", err)
			return nil, "", err
		}
		switch res := res.(type) {
		case *TokenDetails:
			return res, "", nil
		case *TokenRequest:
			tokReq = res
			tokReqClientID = tokReq.ClientID
		}
	default:
		a.log().Verbose("Auth: using default token request")

		req, err := a.createTokenRequest(tokenParams, authOpts)
		if err != nil {
			return nil, "", err
		}
		tokReq = req
	}
	tok = &TokenDetails{}
	r := &request{
		Method: "POST",
		Path:   "/keys/" + tokReq.KeyName + "/requestToken",
		In:     tokReq,
		Out:    tok,
		NoAuth: true,
	}
	if _, err := a.client.do(ctx, r); err != nil {
		return nil, "", err
	}
	return tok, tokReqClientID, nil
}

// Authorize performs authorization with ably service and returns the
// authorization token details.
//
// Refers to RSA10
func (a *Auth) Authorize(ctx context.Context, params *TokenParams, setOpts ...AuthOption) (*TokenDetails, error) {
	var opts *authOptions
	if setOpts != nil {
		opts = applyAuthOptionsWithDefaults(setOpts...)
	}
	a.mtx.Lock()
	// RSA10a - create token immediately using forceCreateNewToken
	token, err := a.authorize(ctx, params, opts, true)
	a.mtx.Unlock()
	if err != nil {
		return nil, err
	}
	a.onExplicitAuthorize(ctx, token)
	return token, nil
}

func (a *Auth) authorize(ctx context.Context, tokenParams *TokenParams, authOpts *authOptions, forceCreateNewToken bool) (*TokenDetails, error) {
	// use existing tokenDetails, if non-forced and token is non-nil and non-expired
	if !forceCreateNewToken {
		if tokenDetails := a.token(); tokenDetails != nil && (tokenDetails.Expires == 0 || !tokenDetails.expired(a.opts().Now())) {
			return tokenDetails, nil
		}
	}

	a.log().Info("Auth: sending  token request")
	tokenDetails, tokReqClientID, err := a.requestToken(ctx, tokenParams, authOpts)
	if err != nil {
		a.log().Error("Auth: failed to get token", err)
		return nil, err
	}

	// Fail if identifiable authClientID notEqual to identifiable tokenDetails/tokenRequest clientID
	notEqual := func(clientId1 string, clientId2 string) bool {
		return identifiable(clientId1, clientId2) && clientId1 != clientId2
	}
	if notEqual(a.clientID, tokenDetails.ClientID) || notEqual(tokReqClientID, tokenDetails.ClientID) {
		a.log().Error("Auth: ", errClientIDMismatch)
		return nil, newError(ErrInvalidClientID, errClientIDMismatch)
	}

	// RSA12a, RSA7b2 - set clientID as per tokenDetails, can be null/non-null/wildcard
	a.updateClientID(tokenDetails.ClientID)

	// RSA10a - use token auth for all future requests
	a.method = authToken

	// RSA10j, RSA10g - if arguments present, override existing tokenParams and authOptions, ignore timestamp and queryTime
	if tokenParams != nil {
		tokenParams.Timestamp = 0
		a.params = tokenParams
	}
	if authOpts != nil {
		authOpts.UseQueryTime = a.opts().UseQueryTime
		a.opts().authOptions = *authOpts
	}
	a.opts().TokenDetails = tokenDetails

	return tokenDetails, nil
}

func (a *Auth) reauthorize(ctx context.Context) (*TokenDetails, error) {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	a.log().Info("Auth: reauthorize")
	return a.authorize(ctx, a.params, nil, true)
}

func (a *Auth) mergeOpts(opts *authOptions) *authOptions {
	if opts == nil {
		opts = &a.opts().authOptions
	} else {
		a.opts().authOptions.merge(opts, false)
	}
	return opts
}

//Timestamp returns the timestamp to be used in authorization request.
func (a *Auth) timestamp(ctx context.Context, query bool) (time.Time, error) {
	now := a.client.opts.Now()
	if !query {
		return now, nil
	}
	if a.serverTimeOffset != 0 {
		// refers to rsa10k
		//
		// No need to do api call for time from the server. We are calculating it
		// using the cached offset(duration) value.
		return now.Add(a.serverTimeOffset), nil
	}
	var serverTime time.Time
	if a.serverTimeHandler != nil {
		t, err := a.serverTimeHandler()
		if err != nil {
			return time.Time{}, newError(ErrUnauthorized, err)
		}
		serverTime = t
	} else {
		t, err := a.client.Time(ctx)
		if err != nil {
			return time.Time{}, newError(ErrUnauthorized, err)
		}
		serverTime = t
	}
	a.serverTimeOffset = serverTime.Sub(now)
	return serverTime, nil
}

func (a *Auth) requestAuthURL(ctx context.Context, params *TokenParams, opts *authOptions) (interface{}, error) {
	req, err := http.NewRequestWithContext(ctx, opts.authHttpMethod(), opts.AuthURL, nil)
	if err != nil {
		return nil, a.newError(40000, err)
	}
	// override auth params while merging
	mergeWithAuthParams := func(params, authParams url.Values) url.Values {
		for key := range authParams {
			if params.Get(key) != "" {
				continue
			}
			params.Set(key, authParams.Get(key))
		}
		return params
	}
	query := mergeWithAuthParams(params.Query(), opts.AuthParams).Encode()

	// override auth headers while merging
	mergeWithAuthHeaders := func(headers, authHeaders http.Header) http.Header {
		for key := range authHeaders {
			if headers.Get(key) != "" {
				continue
			}
			headers.Set(key, authHeaders.Get(key))
		}
		return headers
	}
	req.Header = mergeWithAuthHeaders(req.Header, opts.AuthHeaders)
	switch opts.authHttpMethod() {
	case "GET":
		req.URL.RawQuery = query
	case "POST":
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Content-Length", strconv.Itoa(len(query)))
		req.Body = ioutil.NopCloser(strings.NewReader(query))
	default:
		return nil, a.newError(40500, nil)
	}
	resp, err := a.opts().httpclient().Do(req)
	if err != nil {
		return nil, a.newError(ErrErrorFromClientTokenCallback, err)
	}
	if err = checkValidHTTPResponse(resp); err != nil {
		return nil, a.newError(ErrErrorFromClientTokenCallback, err)
	}
	defer resp.Body.Close()
	typ, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		return nil, a.newError(40004, err)
	}
	switch typ {
	case "text/plain":
		token, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, a.newError(40000, err)
		}
		return newTokenDetails(string(token)), nil
	case protocolJSON, protocolMsgPack:
		var req TokenRequest
		var buf bytes.Buffer
		err := decode(typ, io.TeeReader(resp.Body, &buf), &req)
		if err == nil && req.MAC != "" && req.Nonce != "" {
			return &req, nil
		}
		var token TokenDetails
		if err := decode(typ, io.MultiReader(&buf, resp.Body), &token); err != nil {
			return nil, a.newError(40000, err)
		}
		return &token, nil
	case "":
		return nil, a.newError(40000, errMissingType)
	default:
		return nil, a.newError(40000, errUnsupportedType)
	}
}

func (a *Auth) isTokenRenewable() bool {
	return a.opts().Key != "" || a.opts().AuthURL != "" || a.opts().AuthCallback != nil
}

func (a *Auth) newError(code ErrorCode, err error) error {
	return newError(code, err)
}

func (a *Auth) authReq(req *http.Request) error {
	switch a.method {
	case authBasic:
		req.SetBasicAuth(a.opts().KeyName(), a.opts().KeySecret())
	case authToken:
		if _, err := a.authorize(req.Context(), a.params, nil, false); err != nil {
			return err
		}
		encToken := base64.StdEncoding.EncodeToString([]byte(a.token().Token))
		req.Header.Set("Authorization", "Bearer "+encToken)
	}
	return nil
}

func (a *Auth) authQuery(ctx context.Context, query url.Values) error {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	switch a.method {
	case authBasic:
		query.Set("key", a.opts().Key)
	case authToken:
		if _, err := a.authorize(ctx, a.params, nil, false); err != nil {
			return err
		}
		query.Set("access_token", a.token().Token)
	}
	return nil
}

func (a *Auth) opts() *clientOptions {
	return a.client.opts
}

func (a *Auth) token() *TokenDetails {
	return a.opts().TokenDetails
}

func (a *Auth) log() logger {
	return a.client.log
}

func checkIfKeyIsValid(authOptions *authOptions) error {
	if empty(authOptions.Key) {
		return newError(ErrInvalidCredentials, errMissingKey)
	}
	if empty(authOptions.KeyName()) || empty(authOptions.KeySecret()) {
		return newError(ErrIncompatibleCredentials, errInvalidKey)
	}
	return nil
}

func identifiable(clientIDs ...string) bool {
	for _, s := range clientIDs {
		switch s {
		case "", wildcardClientID:
			return false
		}
	}
	return true
}

func (a *Auth) clientIDForMsgCheck() string {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	if a.method == authBasic {
		return wildcardClientID // for Basic Auth no ClientID check is performed
	}
	return a.clientID
}

func isMsgClientIDAllowed(authClientID, msgClientID string) bool {
	return authClientID == wildcardClientID || msgClientID == "" || authClientID == msgClientID
}
