package ably_test

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ably/ably-go/ably"
	"github.com/ably/ably-go/ablytest"
)

func single() *ably.PaginateParams {
	return &ably.PaginateParams{
		Limit:     1,
		Direction: "forwards",
	}
}

func recorder() (*ablytest.RoundTripRecorder, []ably.ClientOption) {
	rec := &ablytest.RoundTripRecorder{}
	return rec, []ably.ClientOption{ably.WithHTTPClient(&http.Client{
		Transport: rec,
	})}
}

func authValue(req *http.Request) (value string, err error) {
	auth := req.Header.Get("Authorization")
	if i := strings.IndexRune(auth, ' '); i != -1 {
		p, err := base64.StdEncoding.DecodeString(auth[i+1:])
		if err != nil {
			return "", errors.New("failed to base64 decode Authorization header value: " + err.Error())
		}
		auth = string(p)
	}
	return auth, nil
}

func TestAuth_BasicAuth(t *testing.T) {
	t.Parallel()
	rec, extraOpt := recorder()
	defer rec.Stop()
	opts := []ably.ClientOption{ably.WithQueryTime(true)}
	app, client := ablytest.NewREST(append(opts, extraOpt...)...)
	defer safeclose(t, app)

	if _, err := client.Time(context.Background()); err != nil {
		t.Fatalf("client.Time()=%v", err)
	}
	if _, err := client.Stats().Pages(context.Background()); err != nil {
		t.Fatalf("client.Stats()=%v", err)
	}
	if n := rec.Len(); n != 2 {
		t.Fatalf("want rec.Len()=2; got %d", n)
	}
	if method := client.Auth.Method(); method != ably.AuthBasic {
		t.Fatalf("want method=1; got %d", method)
	}
	url := rec.Request(1).URL
	if url.Scheme != "https" {
		t.Fatalf("want url.Scheme=https; got %s", url.Scheme)
	}
	auth, err := authValue(rec.Request(1))
	if err != nil {
		t.Fatalf("authValue=%v", err)
	}
	if key := app.Key(); auth != key {
		t.Fatalf("want auth=%q; got %q", key, auth)
	}
	// Can't use basic auth over HTTP.
	switch _, err := ably.NewREST(app.Options(ably.WithTLS(false))...); {
	case err == nil:
		t.Fatal("want err != nil")
	case ably.UnwrapErrorCode(err) != 40103:
		t.Fatalf("want code=40103; got %d", ably.UnwrapErrorCode(err))
	}
}

func timeWithin(t, start, end time.Time) error {
	if t.Before(start) || t.After(end) {
		return fmt.Errorf("want t=%v to be within [%v, %v] time span", t, start, end)
	}
	return nil
}

func TestAuth_TokenAuth_RSA5(t *testing.T) {
	t.Parallel()
	rec, extraOpt := recorder()
	defer rec.Stop()
	opts := []ably.ClientOption{
		ably.WithTLS(false),
		ably.WithUseTokenAuth(true),
		ably.WithQueryTime(true),
	}
	app, client := ablytest.NewREST(append(opts, extraOpt...)...)
	defer safeclose(t, app)

	if _, err := client.Time(context.Background()); err != nil {
		t.Fatalf("client.Time()=%v", err)
	}
	if _, err := client.Stats().Pages(context.Background()); err != nil {
		t.Fatalf("client.Stats()=%v", err)
	}
	// At this points there should be two requests recorded:
	//
	//   - first: explicit call to Time()
	//   - second: implicit call to Time() during token request
	//   - third: token request
	//   - fourth: actual stats request
	//
	assertEquals(t, 4, rec.Len())
	assertEquals(t, ably.AuthToken, client.Auth.Method())
	assertEquals(t, "http", rec.Request(3).URL.Scheme)

	rec.Reset()

	tok, err := client.Auth.Authorize(context.Background(), nil)
	assertNil(t, err)
	// Call to Authorize should always refresh the token.
	assertEquals(t, 1, rec.Len()) // Authorize should return new token with HTTP call recorded
	assertEquals(t, ably.AuthToken, client.Auth.Method())

	if defaultCap := `{"*":["*"]}`; tok.Capability != defaultCap {
		t.Fatalf("want tok.Capability=%v; got %v", defaultCap, tok.Capability)
	}

	beforeAuth := time.Now().Add(-time.Second)
	now := time.Now().Add(time.Second)
	err = timeWithin(tok.IssueTime(), beforeAuth, now)
	assertNil(t, err)

	// Ensure token expires in 60m (default TTL).
	beforeAuth = beforeAuth.Add(60 * time.Minute)
	now = now.Add(60 * time.Minute)
	err = timeWithin(tok.ExpireTime(), beforeAuth, now)
	assertNil(t, err)
}

func TestAuth_RSA10(t *testing.T) {
	t.Run("RSA10a, RSA10f, RSA10h: instructs library to create token immediately and token auth is used for subsequent requests, returns tokenDetails (token + token metadata)", func(t *testing.T) {
		t.Parallel()
		rec, extraOpt := recorder()
		defer rec.Stop()
		clientId := "authClientId"
		opts := []ably.ClientOption{
			ably.WithTLS(true),
			ably.WithUseTokenAuth(true),
			ably.WithQueryTime(true),
			ably.WithClientID(clientId),
		}
		app, client := ablytest.NewREST(append(opts, extraOpt...)...)
		defer safeclose(t, app)

		assertEquals(t, clientId, client.Auth.ClientID()) // make sure auth client ID is set

		tokenDetails, err := client.Auth.Authorize(context.Background(), nil) // Call to Authorize should always refresh the token.
		assertNil(t, err)
		// RSA10a
		assertEquals(t, 2, rec.Len()) // Authorize should return new token with HTTP call recorded
		assertEquals(t, "https", rec.Request(0).URL.Scheme)
		assertEquals(t, ably.AuthToken, client.Auth.Method())

		rec.Reset()

		newTokenDetails, err := client.Auth.Authorize(context.Background(), nil) // Call to Authorize should always refresh the token.
		assertNil(t, err)

		// RSA10a - new token generated with new tokenDetails/token
		assertEquals(t, 1, rec.Len())
		assertEquals(t, ably.AuthToken, client.Auth.Method())
		assertNotEquals(t, tokenDetails, newTokenDetails) // should generate new tokenDetails for each authorize call
		assertNotEquals(t, tokenDetails.Token, newTokenDetails.Token)

		// RSA10f - should contain token and token metadata
		checkTokenDetails := func(tokenDetails *ably.TokenDetails) {
			assertNotNil(t, tokenDetails)
			assertNotEmpty(t, tokenDetails.Token)
			assertNotZero(t, tokenDetails.Expires)
			assertNotZero(t, tokenDetails.Issued)
			assertNotEmpty(t, tokenDetails.ClientID)
		}
		checkTokenDetails(tokenDetails)
		checkTokenDetails(newTokenDetails)

		// RSA10h - should set auth.ClientId if present
		assertEquals(t, client.Auth.ClientID(), tokenDetails.ClientID)
		assertEquals(t, client.Auth.ClientID(), newTokenDetails.ClientID)
	})

	t.Run("RSA10b : supports all AuthOptions and TokenParams in the function arguments", func(t *testing.T) {
		t.Skip("No need to write tests for the spec since, Auth.Authorize accepts all arguments")
	})

	t.Run("RSA10j, RSA10g: stores given arguments as defaults for subsequent authorizations with exception of tokenParams timestamp and queryTime", func(t *testing.T) {
		t.Parallel()
		rec, extraOpt := recorder()
		defer rec.Stop()

		opts := []ably.ClientOption{
			ably.WithTLS(true),
			ably.WithUseTokenAuth(true),
			ably.WithQueryTime(false),
		}

		app, client := ablytest.NewREST(append(opts, extraOpt...)...)
		defer safeclose(t, app)

		prevTokenParams := client.Auth.Params()
		prevAuthOptions := client.Auth.AuthOptions()
		prevUseQueryTime := prevAuthOptions.UseQueryTime

		tokenParams := &ably.TokenParams{
			TTL:        123890,
			Capability: `{"foo":["publish"]}`,
			ClientID:   "abcd1234",
			Timestamp:  time.Now().UnixNano() / int64(time.Millisecond),
		}

		newAuthOptions := []ably.AuthOption{
			ably.AuthWithMethod("POST"),
			ably.AuthWithQueryTime(true),
			ably.AuthWithKey(app.Key()),
		}

		_, err := client.Auth.Authorize(context.Background(), tokenParams, newAuthOptions...) // Call to Authorize should always refresh the token.
		assertNil(t, err)
		updatedParams := client.Auth.Params()
		updatedAuthOptions := client.Auth.AuthOptions()

		assertNil(t, prevTokenParams)
		assertEquals(t, tokenParams, updatedParams) // RSA10J
		assertZero(t, updatedParams.Timestamp)      // RSA10g

		assertEquals(t, prevAuthOptions, updatedAuthOptions)                  // RSA10J
		assertNotEquals(t, prevUseQueryTime, updatedAuthOptions.UseQueryTime) // RSA10g
	})

	t.Run("RSA10e: returns token if present in authOptions, or should try one of the given authOption", func(t *testing.T) {
		t.Parallel()

		opts := []ably.ClientOption{
			ably.WithEnvironment(ablytest.Environment),
			ably.WithTLS(false),
			ably.WithUseTokenAuth(true),
			ably.WithKey("fake:key"), //provide token
		}

		client, err := ably.NewREST(opts...)
		assertNil(t, err)

		// Should return given token
		newAuthOptions := []ably.AuthOption{
			ably.AuthWithToken("fake:token"),
		}
		tokenDetails, err := client.Auth.Authorize(context.Background(), nil, newAuthOptions...)
		assertEquals(t, "fake:token", tokenDetails.Token)

		// should return given tokenDetails
		tokenDetails = &ably.TokenDetails{
			Token: "fake:token1",
		}

		newAuthOptions = []ably.AuthOption{
			ably.AuthWithTokenDetails(tokenDetails),
		}
		newTokenDetails, err := client.Auth.Authorize(context.Background(), nil, newAuthOptions...)
		assertEquals(t, tokenDetails, newTokenDetails)
	})

	t.Run("RSA10k", func(t *testing.T) {
		t.Parallel()
		now, err := time.Parse(time.RFC822, time.RFC822)
		assertNil(t, err)

		t.Run("must use local time when UseQueryTime is false", func(t *testing.T) {
			t.Parallel()
			rest, err := ably.NewREST(
				ably.WithKey("fake:key"),
				ably.WithNow(func() time.Time {
					return now
				}))
			assertNil(t, err)
			rest.Auth.SetServerTimeFunc(func() (time.Time, error) {
				return now.Add(time.Minute), nil
			})

			timestamp, err := rest.Auth.Timestamp(context.Background(), false)
			assertNil(t, err)
			if !timestamp.Equal(now) {
				t.Errorf("expected %s got %s", now, timestamp)
			}
		})

		t.Run("must use server time when UseQueryTime is true", func(t *testing.T) {
			t.Parallel()

			rest, err := ably.NewREST(
				ably.WithKey("fake:key"),
				ably.WithNow(func() time.Time {
					return now
				}))
			assertNil(t, err)

			rest.Auth.SetServerTimeFunc(func() (time.Time, error) {
				return now.Add(time.Minute), nil
			})

			timestamp, err := rest.Timestamp(true)
			assertNil(t, err)

			serverTime := now.Add(time.Minute)
			if !timestamp.Equal(serverTime) {
				t.Errorf("expected %s got %s", serverTime, timestamp)
			}
		})

		t.Run("must use server time offset ", func(t *testing.T) {
			t.Parallel()

			now := now
			rest, err := ably.NewREST(
				ably.WithKey("fake:key"),
				ably.WithNow(func() time.Time {
					return now
				}))
			assertNil(t, err)
			rest.Auth.SetServerTimeFunc(func() (time.Time, error) {
				return now.Add(time.Minute), nil
			})

			timestamp, err := rest.Timestamp(true)
			assertNil(t, err)
			serverTime := now.Add(time.Minute)
			if !timestamp.Equal(serverTime) {
				t.Errorf("expected %s got %s", serverTime, timestamp)
			}

			now = now.Add(time.Minute)
			rest.Auth.SetServerTimeFunc(func() (time.Time, error) {
				return time.Time{}, errors.New("must not be called")
			})
			timestamp, err = rest.Timestamp(true)
			assertNil(t, err)
			serverTime = now.Add(time.Minute)
			if !timestamp.Equal(serverTime) {
				t.Errorf("expected %s got %s", serverTime, timestamp)
			}
		})
	})

	t.Run("RSA10i: Adheres to all requirements in RSA8 relating to TokenParams, authCallback and authUrl", func(t *testing.T) {
		t.Skip("No need to write tests since covered as a part of RSA8")
	})

	t.Run("RSA10l: Deprecate RestClient#authorise and RealtimeClient#authorise", func(t *testing.T) {
		t.Skip("No need to write tests, since we don't have old 1.0 API available in the first place")
	})
}

func TestAuth_TokenAuth_Renew_When_Expired_RSA4b(t *testing.T) {
	t.Parallel()
	rec, extraOpt := recorder()
	defer rec.Stop()
	opts := []ably.ClientOption{ably.WithUseTokenAuth(true)}
	app, client := ablytest.NewREST(append(opts, extraOpt...)...)
	defer safeclose(t, app)

	params := &ably.TokenParams{
		TTL: time.Second.Milliseconds(),
	}
	tok, err := client.Auth.Authorize(context.Background(), params)
	if err != nil {
		t.Fatalf("Authorize()=%v", err)
	}
	if n := rec.Len(); n != 1 {
		t.Fatalf("want rec.Len()=1; got %d", n)
	}
	if ttl := tok.ExpireTime().Sub(tok.IssueTime()); ttl > 2*time.Second {
		t.Fatalf("want ttl=1s; got %v", ttl)
	}
	time.Sleep(2 * time.Second) // wait till expires
	_, err = client.Stats().Pages(context.Background())
	if err != nil {
		t.Fatalf("Stats()=%v", err)
	}
	// Recorded responses:
	//
	//   - 0: response for explicit Authorize()
	//   - 1: response for implicit Authorize() (token renewal)
	//   - 2: response for Stats()
	//
	if n := rec.Len(); n != 3 {
		t.Fatalf("token not renewed; want rec.Len()=3; got %d", n)
	}
	var newTok ably.TokenDetails
	if err := ably.DecodeResp(rec.Response(1), &newTok); err != nil {
		t.Fatalf("token decode error: %v", err)
	}
	if tok.Token == newTok.Token {
		t.Fatalf("token not renewed; new token equals old: %s", tok.Token)
	}
	// Ensure token was renewed with original params.
	if ttl := newTok.ExpireTime().Sub(newTok.IssueTime()); ttl > 2*time.Second {
		t.Fatalf("want ttl=1s; got %v", ttl)
	}
	time.Sleep(2 * time.Second) // wait for token to expire
	// Ensure request fails when Token or *TokenDetails is provided, but no
	// means to renew the token
	rec.Reset()
	opts = app.Options(opts...)
	opts = append(opts, ably.WithKey(""), ably.WithTokenDetails(tok))
	client, err = ably.NewREST(opts...)
	if err != nil {
		t.Fatalf("NewREST()=%v", err)
	}
	if _, err := client.Stats().Pages(context.Background()); err == nil {
		t.Fatal("want err!=nil")
	}
	// Ensure no requests were made to Ably servers.
	if n := rec.Len(); n != 0 {
		t.Fatalf("want rec.Len()=0; got %d", n)
	}
}

func TestAuth_RequestToken_RSA8(t *testing.T) {
	t.Parallel()
	rec, extraOpt := recorder()
	opts := []ably.ClientOption{
		ably.WithUseTokenAuth(true),
		ably.WithAuthParams(url.Values{"param_1": []string{"this", "should", "get", "overwritten"}}),
	}
	defer rec.Stop()
	app, client := ablytest.NewREST(append(opts, extraOpt...)...)
	defer safeclose(t, app)
	server := ablytest.MustAuthReverseProxy(app.Options(append(opts, extraOpt...)...)...)
	defer safeclose(t, server)

	if n := rec.Len(); n != 0 {
		t.Fatalf("want rec.Len()=0; got %d", n)
	}
	token, err := client.Auth.RequestToken(context.Background(), nil)
	if err != nil {
		t.Fatalf("RequestToken()=%v", err)
	}
	if n := rec.Len(); n != 1 {
		t.Fatalf("want rec.Len()=1; got %d", n)
	}
	// Enqueue token in the auth reverse proxy - expect it'd be received in response
	// to AuthURL request.
	server.TokenQueue = append(server.TokenQueue, token)
	authOpts := []ably.AuthOption{
		ably.AuthWithURL(server.URL("details")),
	}
	token2, err := client.Auth.RequestToken(context.Background(), nil, authOpts...)
	if err != nil {
		t.Fatalf("RequestToken()=%v", err)
	}
	// Ensure token was requested from AuthURL.
	if n := rec.Len(); n != 2 {
		t.Fatalf("want rec.Len()=2; got %d", n)
	}
	if got, want := rec.Request(1).URL.Host, server.Listener.Addr().String(); got != want {
		t.Fatalf("want request.URL.Host=%s; got %s", want, got)
	}
	// Again enqueue received token in the auth reverse proxy - expect it'd be returned
	// by the AuthCallback.
	//
	// For "token" and "details" callback the TokenDetails value is obtained from
	// token2, thus token2 and tokCallback are the same.
	rec.Reset()
	for _, callback := range []string{"token", "details"} {
		server.TokenQueue = append(server.TokenQueue, token2)
		authOpts := []ably.AuthOption{
			ably.AuthWithCallback(server.Callback(callback)),
		}
		tokCallback, err := client.Auth.RequestToken(context.Background(), nil, authOpts...)
		if err != nil {
			t.Fatalf("RequestToken()=%v (callback=%s)", err, callback)
		}
		// Ensure no requests to Ably servers were made.
		if n := rec.Len(); n != 0 {
			t.Fatalf("want rec.Len()=0; got %d (callback=%s)", n, callback)
		}
		// Ensure all tokens received from RequestToken are equal.
		if !reflect.DeepEqual(token, token2) {
			t.Fatalf("want token=%v == token2=%v (callback=%s)", token, token2, callback)
		}
		if token2.Token != tokCallback.Token {
			t.Fatalf("want token2.Token=%s == tokCallback.Token=%s (callback=%s)",
				token2.Token, tokCallback.Token, callback)
		}
	}
	// For "request" callback, a TokenRequest value is created from the token2,
	// then it's used to request TokenDetails from the Ably servers.
	server.TokenQueue = append(server.TokenQueue, token2)
	authOpts = []ably.AuthOption{
		ably.AuthWithCallback(server.Callback("request")),
	}
	tokCallback, err := client.Auth.RequestToken(context.Background(), nil, authOpts...)
	if err != nil {
		t.Fatalf("RequestToken()=%v", err)
	}
	if n := rec.Len(); n != 1 {
		t.Fatalf("want rec.Len()=1; got %d", n)
	}
	if token2.Token == tokCallback.Token {
		t.Fatalf("want token2.Token2=%s != tokCallback.Token=%s", token2.Token, tokCallback.Token)
	}
	// Ensure all headers and params are sent with request to AuthURL.
	for _, method := range []string{"GET", "POST"} {
		// Each iteration records the requests:
		//
		//  0 - RequestToken: request to AuthURL
		//  1 - RequestToken: proxied Auth request to Ably servers
		//  2 - Stats request to Ably API
		//
		// Responses are analogously ordered.
		rec.Reset()
		authHeaders := http.Header{"X-Header-1": {"header"}, "X-Header-2": {"header"}}
		authParams := url.Values{
			"param_1":  {"value"},
			"param_2":  {"value"},
			"clientId": {"should not be overwritten"},
		}
		authOpts = []ably.AuthOption{
			ably.AuthWithMethod(method),
			ably.AuthWithURL(server.URL("request")),
			ably.AuthWithHeaders(authHeaders),
			ably.AuthWithParams(authParams),
		}
		params := &ably.TokenParams{
			ClientID: "test",
		}

		tokURL, err := client.Auth.RequestToken(context.Background(), params, authOpts...)
		if err != nil {
			t.Fatalf("RequestToken()=%v (method=%s)", err, method)
		}
		if tokURL.Token == token2.Token {
			t.Fatalf("want tokURL.Token != token2.Token: %s (method=%s)", tokURL.Token, method)
		}
		req := rec.Request(0)
		if req.Method != method {
			t.Fatalf("want req.Method=%s; got %s", method, req.Method)
		}
		for k := range authHeaders {
			if got, want := req.Header.Get(k), authHeaders.Get(k); got != want {
				t.Errorf("want %s; got %s (method=%s)", want, got, method)
			}
		}
		query := ablytest.MustQuery(req)
		for k := range authParams {
			if k == "clientId" {
				if got := query.Get(k); got != params.ClientID {
					t.Errorf("want client_id=%q to be not overwritten; it was: %q (method=%s)",
						params.ClientID, got, method)
				}
				continue
			}
			if got, want := query.Get(k), authParams.Get(k); got != want {
				t.Errorf("param:%s; want %q; got %q (method=%s)", k, want, got, method)
			}
		}
		var tokReq ably.TokenRequest
		if err := ably.DecodeResp(rec.Response(1), &tokReq); err != nil {
			t.Errorf("token request decode error: %v (method=%s)", err, method)
		}
		if tokReq.ClientID != "test" {
			t.Errorf("want clientID=test; got %v (method=%s)", tokReq.ClientID, method)
		}
		// Call the API with the token obtained via AuthURL.
		optsURL := append(app.Options(opts...),
			ably.WithToken(tokURL.Token),
		)
		c, err := ably.NewREST(optsURL...)
		if err != nil {
			t.Errorf("NewRealtime()=%v", err)
			continue
		}
		if _, err = c.Stats().Pages(context.Background()); err != nil {
			t.Errorf("c.Stats()=%v (method=%s)", err, method)
		}
	}
}

func TestAuth_ClientID_Error(t *testing.T) {
	t.Parallel()
	opts := []ably.ClientOption{
		ably.WithClientID("*"),
		ably.WithKey("abc:abc"),
		ably.WithUseTokenAuth(true),
	}
	_, err := ably.NewRealtime(opts...)
	assertErrorCode(t, 40102, err)
}

func TestAuth_ReuseClientID(t *testing.T) {
	t.Parallel()
	opts := []ably.ClientOption{ably.WithUseTokenAuth(true)}
	app, client := ablytest.NewREST(opts...)
	defer safeclose(t, app)

	params := &ably.TokenParams{
		ClientID: "reuse-me",
	}
	tok, err := client.Auth.Authorize(context.Background(), params)
	if err != nil {
		t.Fatalf("Authorize()=%v", err)
	}
	if tok.ClientID != params.ClientID {
		t.Fatalf("want ClientID=%q; got %q", params.ClientID, tok.ClientID)
	}
	if clientID := client.Auth.ClientID(); clientID != params.ClientID {
		t.Fatalf("want ClientID=%q; got %q", params.ClientID, tok.ClientID)
	}
	tok2, err := client.Auth.Authorize(context.Background(), nil)
	if err != nil {
		t.Fatalf("Authorize()=%v", err)
	}
	if tok2.ClientID != params.ClientID {
		t.Fatalf("want ClientID=%q; got %q", params.ClientID, tok2.ClientID)
	}
}

func TestAuth_RequestToken_PublishClientID(t *testing.T) {
	t.Parallel()
	app := ablytest.MustSandbox(nil)
	defer safeclose(t, app)
	cases := []struct {
		authAs    string
		publishAs string
		clientID  string
		rejected  bool
	}{
		{"", "", "", false},                         // i=0
		{"", "explicit", "", true},                  // i=1
		{"*", "", "", false},                        // i=2
		{"*", "explicit", "", false},                // i=3
		{"explicit", "different", "explicit", true}, // i=4
	}

	for i, cas := range cases {
		rclient, err := ably.NewREST(app.Options()...)
		if err != nil {
			t.Fatal(err)
		}
		params := &ably.TokenParams{
			ClientID: cas.authAs,
		}
		tok, err := rclient.Auth.RequestToken(context.Background(), params)
		if err != nil {
			t.Errorf("%d: CreateTokenRequest()=%v", i, err)
			continue
		}
		opts := []ably.ClientOption{
			ably.WithTokenDetails(tok),
			ably.WithUseTokenAuth(true),
		}
		if i == 4 {
			opts = append(opts, ably.WithClientID(cas.clientID))
		}
		client := app.NewRealtime(opts...)
		defer safeclose(t, ablytest.FullRealtimeCloser(client))
		if err = ablytest.Wait(ablytest.ConnWaiter(client, client.Connect, ably.ConnectionEventConnected), nil); err != nil {
			t.Fatalf("Connect(): want err == nil got err=%v", err)
		}
		if id := client.Auth.ClientID(); id != cas.clientID {
			t.Errorf("%d: want ClientID to be %q; got %s", i, cas.clientID, id)
			continue
		}
		channel := client.Channels.Get("publish")
		if err := channel.Attach(context.Background()); err != nil {
			t.Fatal(err)
		}
		messages, unsub, err := ablytest.ReceiveMessages(channel, "test")
		defer unsub()
		if err != nil {
			t.Errorf("%d:.Subscribe(context.Background())=%v", i, err)
			continue
		}
		msg := []*ably.Message{{
			ClientID: cas.publishAs,
			Name:     "test",
			Data:     "payload",
		}}
		err = channel.PublishMultiple(context.Background(), msg)
		if cas.rejected {
			if err == nil {
				t.Errorf("%d: expected message to be rejected %#v", i, cas)
			}
			continue
		}
		if err != nil {
			t.Errorf("%d: PublishMultiple()=%v", i, err)
			continue
		}
		select {
		case msg := <-messages:
			if msg.ClientID != cas.publishAs {
				t.Errorf("%d: want ClientID=%q; got %q", i, cas.publishAs, msg.ClientID)
			}
		case <-time.After(ablytest.Timeout):
			t.Errorf("%d: waiting for message timed out after %v", i, ablytest.Timeout)
		}
	}
}

func TestAuth_ClientID_RSA7(t *testing.T) {
	t.Parallel()

	t.Run("RSA7d: tokenParams clientID should be set with provided clientID while requesting a token", func(t *testing.T) {

	})

	t.Run("RSA7e: when clientID is provided in clientOptions with basic auth", func(t *testing.T) {
		t.Run("RSA7e1: for realtime clients, connect request should include clientID as querystring param", func(t *testing.T) {

		})
		t.Run("RSA7e2: for rest clients, X-Ably-ClientId header should be set with base64 encoded clientID", func(t *testing.T) {

		})
	})

	t.Run("RSA7a: for identified clients", func(t *testing.T) {
		t.Run("RSA7a1: messageID should not be set for published messages", func(t *testing.T) {

		})
		t.Run("RSA7a2: override defaultTokenParams clientID with clientOptions clientID if provided", func(t *testing.T) {

		})
	})

	t.Run("RSA7b: auth clientID is set when", func(t *testing.T) {
		t.Run("RSA7b1, RSA12b: clientID is provided in ClientOptions clientID", func(t *testing.T) {

		})

		t.Run("RSA7b2, RSA12a: tokenRequest/tokenDetails obtained has clientID", func(t *testing.T) {

		})
		t.Run("RSA7b3, RSA12a: connected ProtocolMessage#connectionDetails contains clientID", func(t *testing.T) {
			in := make(chan *ably.ProtocolMessage, 16)
			out := make(chan *ably.ProtocolMessage, 16)
			client, err := ably.NewRealtime(
				ably.WithTLS(false),
				ably.WithToken("fake:token"),
				ably.WithUseTokenAuth(true),
				ably.WithDial(MessagePipe(in, out)))
			assertNil(t, err)

			// prev, auth clientID is not set
			id := client.Auth.ClientID()
			assertEmpty(t, id)

			connected := &ably.ProtocolMessage{
				Action:       ably.ActionConnected,
				ConnectionID: "connection-id",
				ConnectionDetails: &ably.ConnectionDetails{
					ClientID: "client-id",
				},
			}

			// Ensure CONNECTED message updates clientID
			in <- connected
			err = ablytest.Wait(ablytest.ConnWaiter(client, client.Connect, ably.ConnectionEventConnected), nil)
			assertNil(t, err)
			assertEquals(t, connected.ConnectionDetails.ClientID, client.Auth.ClientID())
		})

		t.Run("RSA7b4: tokenDetails/connectionDetails has * as wildCardClientID", func(t *testing.T) {

		})
	})

	t.Run("RSA7c: error on providing wildcard clientID in clientOptions", func(t *testing.T) {
		t.Parallel()
		app := ablytest.MustSandbox(nil)
		defer safeclose(t, app)
		opts := app.Options()
		opts = append(opts, ably.WithClientID("*"))
		_, err := ably.NewREST(opts...)
		assertErrorCode(t, 40102, err)
	})
}

func TestAuth_RSA15(t *testing.T) {
	in := make(chan *ably.ProtocolMessage, 16)
	out := make(chan *ably.ProtocolMessage, 16)
	app := ablytest.MustSandbox(nil)
	defer safeclose(t, app)

	proxy := ablytest.MustAuthReverseProxy(app.Options(ably.WithUseTokenAuth(true))...)
	defer safeclose(t, proxy)

	params := &ably.TokenParams{
		TTL: time.Second.Milliseconds(),
	}

	opts := []ably.ClientOption{
		ably.WithAuthURL(proxy.URL("details")),
		ably.WithUseTokenAuth(true),
		ably.WithDial(MessagePipe(in, out)),
		ably.WithAutoConnect(false),
	}

	client := app.NewRealtime(opts...) // no client.Close as the connection is mocked

	// Mock the auth reverse proxy to return a token with non-matching ClientID
	// via AuthURL.
	tok, err := client.Auth.RequestToken(context.Background(), params)
	assertNil(t, err)

	tok.ClientID = "matching"
	proxy.TokenQueue = append(proxy.TokenQueue, tok)

	// received and adds queued token to the client
	_, err = client.Auth.Authorize(context.Background(), nil)
	assertNil(t, err)

	tok.ClientID = "non-matching"
	proxy.TokenQueue = append(proxy.TokenQueue, tok)

	_, err = client.Auth.Authorize(context.Background(), nil)
	assertErrorCode(t, 40012, err)

	err = ablytest.Wait(ablytest.AssertionWaiter(func() bool {
		return tok.Expired(time.Now())
	}), nil)
	assertNil(t, err)
	//connectedMsg := &ably.ProtocolMessage {
	//	Action:       ably.ActionConnected,
	//	ConnectionID: "connection-id",
	//	ConnectionDetails: &ably.ConnectionDetails{
	//		ClientID: "client-id",
	//	},
	//}
	//
	//in <- connectedMsg
	proxy.TokenQueue = append(proxy.TokenQueue, tok)
	err = ablytest.Wait(ablytest.ConnWaiter(client, client.Connect, ably.ConnectionEventFailed), nil)

	assertErrorCode(t, 40012, err)
	assertEquals(t, ably.ConnectionStateFailed, client.Connection.State())
}

func TestAuth_CreateTokenRequest(t *testing.T) {
	t.Parallel()
	app, client := ablytest.NewREST()
	defer safeclose(t, app)

	opts := []ably.AuthOption{
		ably.AuthWithQueryTime(true),
		ably.AuthWithKey(app.Key()),
	}
	params := &ably.TokenParams{
		TTL:        (5 * time.Second).Milliseconds(),
		Capability: `{"presence":["read", "write"]}`,
	}
	t.Run("RSA9h", func(t *testing.T) {
		t.Run("parameters are optional", func(t *testing.T) {
			_, err := client.Auth.CreateTokenRequest(params)
			if err != nil {
				t.Fatalf("expected no error to occur got %v instead", err)
			}
			_, err = client.Auth.CreateTokenRequest(nil, opts...)
			if err != nil {
				t.Fatalf("expected no error to occur got %v instead", err)
			}
			_, err = client.Auth.CreateTokenRequest(nil)
			if err != nil {
				t.Fatalf("expected no error to occur got %v instead", err)
			}
		})
		t.Run("authOptions must not be merged", func(t *testing.T) {
			opts := []ably.AuthOption{ably.AuthWithQueryTime(true)}
			_, err := client.Auth.CreateTokenRequest(params, opts...)
			if err == nil {
				t.Fatal("expected an error")
			}
			e := err.(*ably.ErrorInfo)
			if e.Code != ably.ErrInvalidCredentials {
				t.Errorf("expected error code %d got %d", ably.ErrInvalidCredentials, e.Code)
			}

			// override with bad key
			opts = append(opts, ably.AuthWithKey("some bad key"))
			_, err = client.Auth.CreateTokenRequest(params, opts...)
			if err == nil {
				t.Fatal("expected an error")
			}
			e = err.(*ably.ErrorInfo)
			if e.Code != ably.ErrIncompatibleCredentials {
				t.Errorf("expected error code %d got %d", ably.ErrIncompatibleCredentials, e.Code)
			}
		})
	})
	t.Run("RSA9c must generate a unique 16+ character nonce", func(t *testing.T) {
		req, err := client.Auth.CreateTokenRequest(params, opts...)
		if err != nil {
			t.Fatalf("CreateTokenRequest()=%v", err)
		}
		if len(req.Nonce) < 16 {
			t.Fatalf("want len(nonce)>=16; got %d", len(req.Nonce))
		}
	})
	t.Run("RSA9g generate a signed request", func(t *testing.T) {
		req, err := client.Auth.CreateTokenRequest(nil)
		if err != nil {
			t.Fatalf("CreateTokenRequest()=%v", err)
		}
		if req.MAC == "" {
			t.Fatalf("want mac to be not empty")
		}
	})
}

func TestAuth_RealtimeAccessToken(t *testing.T) {
	t.Parallel()
	rec := NewMessageRecorder()
	const explicitClientID = "explicit"
	opts := []ably.ClientOption{
		ably.WithClientID(explicitClientID),
		ably.WithAutoConnect(false),
		ably.WithDial(rec.Dial),
		ably.WithUseTokenAuth(true),
	}
	app, client := ablytest.NewRealtime(opts...)
	defer safeclose(t, app)

	if err := ablytest.Wait(ablytest.ConnWaiter(client, client.Connect, ably.ConnectionEventConnected), nil); err != nil {
		t.Fatalf("Connect()=%v", err)
	}
	if err := client.Channels.Get("test").Publish(context.Background(), "name", "value"); err != nil {
		t.Fatalf("Publish()=%v", err)
	}
	if clientID := client.Auth.ClientID(); clientID != explicitClientID {
		t.Fatalf("want ClientID=%q; got %q", explicitClientID, clientID)
	}
	if err := ablytest.FullRealtimeCloser(client).Close(); err != nil {
		t.Fatalf("Close()=%v", err)
	}
	urls := rec.URL()
	if len(urls) == 0 {
		t.Fatal("want urls to be non-empty")
	}
	for _, url := range urls {
		if s := url.Query().Get("accessToken"); s == "" {
			t.Errorf("missing accessToken param in %q", url)
		}
	}
	for _, msg := range rec.Sent() {
		for _, msg := range msg.Messages {
			if msg.ClientID != "" {
				t.Fatalf("want ClientID to be empty; got %q", msg.ClientID)
			}
		}
	}
}
