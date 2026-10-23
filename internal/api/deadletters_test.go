package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sorotrail/sorobeacon/internal/auth"
	"github.com/sorotrail/sorobeacon/internal/notify"
	"github.com/sorotrail/sorobeacon/internal/rules"
	"github.com/sorotrail/sorobeacon/internal/store"
	"github.com/sorotrail/sorobeacon/internal/workspace"
)

// deadLetterNotifier records how many redrives actually reached a channel. A
// redrive is the one API operation that sends a message, so the count is the
// difference between "the handler answered" and "someone was paged".
type deadLetterNotifier struct {
	calls int
	err   error
}

func (n *deadLetterNotifier) Send(context.Context, notify.Alert) error {
	n.calls++
	return n.err
}

type deadLetterFixture struct {
	alert      store.Alert
	channel    store.Channel
	deadLetter store.DeadLetter
}

// seedDeadLetter creates one alert, channel and dead letter in acme. The
// channel config carries a recognisable secret so a listing that leaks it is
// caught by value, not by trusting the response shape.
func seedDeadLetter(t *testing.T, st store.Store) deadLetterFixture {
	t.Helper()
	ctx := workspace.With(context.Background(), workspace.ID("acme"))

	monitors, err := st.ListMonitors(ctx, false)
	require.NoError(t, err)
	require.NotEmpty(t, monitors)
	monitor := monitors[0]

	rule := &store.Rule{MonitorID: monitor.ID, Type: "event_emitted", Params: json.RawMessage(`{}`), Enabled: true}
	require.NoError(t, st.CreateRule(ctx, rule))

	channel := &store.Channel{
		Name:    "ops",
		Type:    "mock",
		Config:  json.RawMessage(`{"webhook_url":"https://hooks.example/SUPER-SECRET-TOKEN"}`),
		Enabled: true,
	}
	require.NoError(t, st.CreateChannel(ctx, channel))

	alert := &store.Alert{
		MonitorID: monitor.ID,
		RuleID:    rule.ID,
		EventID:   "ev-1",
		Payload:   json.RawMessage(`{"contract_id":"C","event_name":"transfer"}`),
	}
	_, err = st.CreateAlert(ctx, alert)
	require.NoError(t, err)

	deadLetter := &store.DeadLetter{
		AlertID:      alert.ID,
		ChannelID:    channel.ID,
		LastError:    "status 401",
		AttemptCount: 3,
		LastStatus:   401,
	}
	require.NoError(t, st.CreateDeadLetter(ctx, deadLetter))

	return deadLetterFixture{alert: *alert, channel: *channel, deadLetter: *deadLetter}
}

func deadLetterServer(t *testing.T, st store.Store, n *deadLetterNotifier) *httptest.Server {
	t.Helper()
	f := notify.DefaultFactory()
	f.Register("mock", func(json.RawMessage) (notify.Notifier, error) { return n, nil })
	s := New(st, rules.NewRegistry(), f, &fakeRPC{}, slog.New(slog.NewTextHandler(io.Discard, nil))).WithAuth(twoWorkspaces())
	srv := httptest.NewServer(s.Routes())
	t.Cleanup(srv.Close)
	return srv
}

func callDeadLetter(t *testing.T, srv *httptest.Server, method, path, token string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+path, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := srv.Client().Do(req)
	require.NoError(t, err)
	raw, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	require.NoError(t, res.Body.Close())
	return res, raw
}

func TestListDeadLettersEmpty(t *testing.T) {
	srv := deadLetterServer(t, newTenantStore(t), &deadLetterNotifier{})

	res, raw := callDeadLetter(t, srv, http.MethodGet, "/dead-letters", acmeToken)
	require.Equal(t, http.StatusOK, res.StatusCode, string(raw))
	assert.JSONEq(t, "[]", string(raw), "an empty queue is an array, not null")

	var got []map[string]any
	require.NoError(t, json.Unmarshal(raw, &got))
	assert.Empty(t, got)
}

func TestListDeadLettersShapePagingAndNoConfigLeak(t *testing.T) {
	st := newTenantStore(t)
	f := seedDeadLetter(t, st)
	ctx := workspace.With(context.Background(), workspace.ID("acme"))

	second := &store.DeadLetter{
		AlertID:      f.alert.ID,
		ChannelID:    f.channel.ID,
		LastError:    "status 500",
		AttemptCount: 2,
		LastStatus:   500,
	}
	require.NoError(t, st.CreateDeadLetter(ctx, second))

	srv := deadLetterServer(t, st, &deadLetterNotifier{})

	res, raw := callDeadLetter(t, srv, http.MethodGet, "/dead-letters", acmeToken)
	require.Equal(t, http.StatusOK, res.StatusCode, string(raw))
	assert.NotContains(t, string(raw), "SUPER-SECRET-TOKEN", "a dead-letter listing must never expose channel config")
	assert.NotContains(t, string(raw), `"config"`, "the response must not carry a channel config field")

	var list []map[string]any
	require.NoError(t, json.Unmarshal(raw, &list))
	require.Len(t, list, 2)
	for _, row := range list {
		assert.NotZero(t, row["id"])
		assert.Equal(t, float64(f.alert.ID), row["alert_id"])
		assert.Equal(t, float64(f.channel.ID), row["channel_id"])
		assert.NotEmpty(t, row["last_error"])
		assert.NotZero(t, row["created_at"])
	}

	// The handler passes filters through to the store and pages in id order.
	res, raw = callDeadLetter(t, srv, http.MethodGet, "/dead-letters?channel_id="+fmt.Sprint(f.channel.ID), acmeToken)
	require.Equal(t, http.StatusOK, res.StatusCode, string(raw))
	require.NoError(t, json.Unmarshal(raw, &list))
	assert.Len(t, list, 2)

	res, raw = callDeadLetter(t, srv, http.MethodGet, "/dead-letters?limit=1", acmeToken)
	require.Equal(t, http.StatusOK, res.StatusCode, string(raw))
	require.NoError(t, json.Unmarshal(raw, &list))
	require.Len(t, list, 1)
	firstID := int64(list[0]["id"].(float64))

	res, raw = callDeadLetter(t, srv, http.MethodGet, fmt.Sprintf("/dead-letters?after_id=%d", firstID), acmeToken)
	require.Equal(t, http.StatusOK, res.StatusCode, string(raw))
	require.NoError(t, json.Unmarshal(raw, &list))
	require.Len(t, list, 1)
	assert.NotEqual(t, firstID, int64(list[0]["id"].(float64)))
}

func TestDeadLettersDoNotCrossTenants(t *testing.T) {
	st := newTenantStore(t)
	f := seedDeadLetter(t, st)
	n := &deadLetterNotifier{}
	srv := deadLetterServer(t, st, n)

	res, raw := callDeadLetter(t, srv, http.MethodGet, "/dead-letters", betaToken)
	require.Equal(t, http.StatusOK, res.StatusCode, string(raw))
	assert.JSONEq(t, "[]", string(raw), "beta must not see acme's dead letter")

	beta := workspace.With(context.Background(), workspace.ID("beta"))
	_, err := st.GetDeadLetter(beta, f.deadLetter.ID)
	assert.ErrorIs(t, err, store.ErrNotFound, "a foreign dead letter is indistinguishable from an unknown id")

	res, raw = callDeadLetter(t, srv, http.MethodPost, fmt.Sprintf("/dead-letters/%d/redrive", f.deadLetter.ID), betaToken)
	require.Equal(t, http.StatusNotFound, res.StatusCode, string(raw))
	assert.Zero(t, n.calls, "a cross-tenant redrive must not send anything")

	res, raw = callDeadLetter(t, srv, http.MethodGet, "/dead-letters", acmeToken)
	require.Equal(t, http.StatusOK, res.StatusCode, string(raw))
	var list []map[string]any
	require.NoError(t, json.Unmarshal(raw, &list))
	require.Len(t, list, 1)
	assert.Equal(t, float64(f.deadLetter.ID), list[0]["id"])
}

func TestRedriveDeadLetterSuccessIsIdempotent(t *testing.T) {
	st := newTenantStore(t)
	f := seedDeadLetter(t, st)
	n := &deadLetterNotifier{}
	srv := deadLetterServer(t, st, n)
	ctx := workspace.With(context.Background(), workspace.ID("acme"))

	path := fmt.Sprintf("/dead-letters/%d/redrive", f.deadLetter.ID)
	res, raw := callDeadLetter(t, srv, http.MethodPost, path, acmeToken)
	require.Equal(t, http.StatusNoContent, res.StatusCode, string(raw))
	assert.Equal(t, 1, n.calls)

	_, err := st.GetDeadLetter(ctx, f.deadLetter.ID)
	assert.ErrorIs(t, err, store.ErrNotFound, "successful redrive removes the dead letter")

	attempts, err := st.ListDeliveryAttempts(ctx, f.alert.ID, "")
	require.NoError(t, err)
	require.Len(t, attempts, 1)
	assert.Equal(t, store.DeliveryStatusSuccess, attempts[0].Status)
	assert.Equal(t, f.channel.ID, attempts[0].ChannelID)

	res, raw = callDeadLetter(t, srv, http.MethodPost, path, acmeToken)
	require.Equal(t, http.StatusNotFound, res.StatusCode, string(raw), "the second redrive must not send again")
	assert.Equal(t, 1, n.calls)
}

func TestRedriveDeadLetterFailureIsRetriedAndReportedSafely(t *testing.T) {
	st := newTenantStore(t)
	f := seedDeadLetter(t, st)
	n := &deadLetterNotifier{err: errors.New("post https://hooks.example/SUPER-SECRET-TOKEN: connection refused")}
	srv := deadLetterServer(t, st, n)
	ctx := workspace.With(context.Background(), workspace.ID("acme"))
	path := fmt.Sprintf("/dead-letters/%d/redrive", f.deadLetter.ID)

	res, raw := callDeadLetter(t, srv, http.MethodPost, path, acmeToken)
	require.Equal(t, http.StatusBadGateway, res.StatusCode, string(raw))
	assert.NotContains(t, string(raw), "SUPER-SECRET-TOKEN", "the API response must not echo the channel secret")
	assert.Contains(t, string(raw), "redrive delivery failed")

	_, err := st.GetDeadLetter(ctx, f.deadLetter.ID)
	require.NoError(t, err, "a failed redrive leaves the dead letter available for another try")
	attempts, err := st.ListDeliveryAttempts(ctx, f.alert.ID, "")
	require.NoError(t, err)
	require.Len(t, attempts, 1)
	assert.Equal(t, store.DeliveryStatusFailed, attempts[0].Status)
	assert.NotContains(t, attempts[0].ResponseSnippet, "SUPER-SECRET-TOKEN")

	// The row is not wedged: once the channel recovers, the same request
	// succeeds and clears it.
	n.err = nil
	res, raw = callDeadLetter(t, srv, http.MethodPost, path, acmeToken)
	require.Equal(t, http.StatusNoContent, res.StatusCode, string(raw))
	assert.Equal(t, 2, n.calls)
	_, err = st.GetDeadLetter(ctx, f.deadLetter.ID)
	assert.ErrorIs(t, err, store.ErrNotFound)
}

func TestRedriveDeadLetterAlreadySucceededClearsStaleRecord(t *testing.T) {
	st := newTenantStore(t)
	f := seedDeadLetter(t, st)
	n := &deadLetterNotifier{}
	srv := deadLetterServer(t, st, n)
	ctx := workspace.With(context.Background(), workspace.ID("acme"))

	require.NoError(t, st.RecordDeliveryAttempt(ctx, &store.DeliveryAttempt{
		AlertID:         f.alert.ID,
		ChannelID:       f.channel.ID,
		Status:          store.DeliveryStatusSuccess,
		ResponseSnippet: "ok",
	}))

	path := fmt.Sprintf("/dead-letters/%d/redrive", f.deadLetter.ID)
	res, raw := callDeadLetter(t, srv, http.MethodPost, path, acmeToken)
	require.Equal(t, http.StatusConflict, res.StatusCode, string(raw))
	assert.Contains(t, string(raw), notify.ErrAlreadySucceeded.Error())
	assert.Zero(t, n.calls, "an already delivered alert must not be sent again")

	_, err := st.GetDeadLetter(ctx, f.deadLetter.ID)
	assert.ErrorIs(t, err, store.ErrNotFound, "the stale dead letter must be cleared, not left unredrivable")

	res, raw = callDeadLetter(t, srv, http.MethodPost, path, acmeToken)
	require.Equal(t, http.StatusNotFound, res.StatusCode, string(raw))
}

func TestRedriveDeadLetterRefusesDisabledChannel(t *testing.T) {
	st := newTenantStore(t)
	f := seedDeadLetter(t, st)
	ctx := workspace.With(context.Background(), workspace.ID("acme"))

	f.channel.Enabled = false
	require.NoError(t, st.UpdateChannel(ctx, &f.channel))

	n := &deadLetterNotifier{}
	srv := deadLetterServer(t, st, n)
	res, raw := callDeadLetter(t, srv, http.MethodPost, fmt.Sprintf("/dead-letters/%d/redrive", f.deadLetter.ID), acmeToken)
	require.Equal(t, http.StatusBadRequest, res.StatusCode, string(raw))
	assert.Contains(t, string(raw), notify.ErrChannelDisabled.Error())
	assert.Zero(t, n.calls)
	_, err := st.GetDeadLetter(ctx, f.deadLetter.ID)
	require.NoError(t, err, "a disabled channel leaves the dead letter for after it is re-enabled")
}

func TestRedriveDeadLetterUnknownAndMalformedIDs(t *testing.T) {
	srv := deadLetterServer(t, newTenantStore(t), &deadLetterNotifier{})

	res, raw := callDeadLetter(t, srv, http.MethodPost, "/dead-letters/not-a-number/redrive", acmeToken)
	require.Equal(t, http.StatusBadRequest, res.StatusCode, string(raw))

	res, raw = callDeadLetter(t, srv, http.MethodPost, "/dead-letters/999999/redrive", acmeToken)
	require.Equal(t, http.StatusNotFound, res.StatusCode, string(raw))
	assert.Contains(t, string(raw), "dead letter not found")
}

type deadLetterErrorStore struct {
	store.Store
	listErr error
	getErr  error
}

func (s *deadLetterErrorStore) ListDeadLetters(context.Context, store.DeadLetterFilter) ([]store.DeadLetter, error) {
	return nil, s.listErr
}

func (s *deadLetterErrorStore) GetDeadLetter(context.Context, int64) (*store.DeadLetter, error) {
	return nil, s.getErr
}

func TestDeadLetterStoreErrorsReturnA500WithoutRawText(t *testing.T) {
	st := newTenantStore(t)
	rawErr := "dial tcp: SUPER-SECRET-TOKEN"

	t.Run("list", func(t *testing.T) {
		srv := deadLetterServer(t, &deadLetterErrorStore{Store: st, listErr: errors.New(rawErr)}, &deadLetterNotifier{})
		res, raw := callDeadLetter(t, srv, http.MethodGet, "/dead-letters", acmeToken)
		require.Equal(t, http.StatusInternalServerError, res.StatusCode, string(raw))
		assert.NotContains(t, string(raw), "SUPER-SECRET-TOKEN")
		assert.Contains(t, string(raw), "internal error")
	})

	t.Run("redrive", func(t *testing.T) {
		srv := deadLetterServer(t, &deadLetterErrorStore{Store: st, getErr: errors.New(rawErr)}, &deadLetterNotifier{})
		res, raw := callDeadLetter(t, srv, http.MethodPost, "/dead-letters/1/redrive", acmeToken)
		require.Equal(t, http.StatusInternalServerError, res.StatusCode, string(raw))
		assert.NotContains(t, string(raw), "SUPER-SECRET-TOKEN")
		assert.Contains(t, string(raw), "internal error")
	})
}

func TestErrorsIsNotFoundRecognisesWrappedNotFound(t *testing.T) {
	assert.True(t, errorsIsNotFound(fmt.Errorf("get dead letter: %w", store.ErrNotFound)))
	assert.False(t, errorsIsNotFound(errors.New("not found")))
	assert.False(t, errorsIsNotFound(nil))
}

func TestDeadLetterRoutesRequireTheExpectedRoleAndScope(t *testing.T) {
	role, ok := routeRoles.Lookup(http.MethodGet, "/dead-letters")
	require.True(t, ok)
	assert.Equal(t, auth.RoleViewer, role)

	role, ok = routeRoles.Lookup(http.MethodPost, "/dead-letters/{id}/redrive")
	require.True(t, ok)
	assert.Equal(t, auth.RoleEditor, role, "redrive sends a notification, so a viewer must not reach it")

	scopes, ok := routeScopes.Lookup(http.MethodGet, "/dead-letters")
	require.True(t, ok)
	assert.Equal(t, []auth.Scope{auth.ScopeAlertsRead}, scopes)

	scopes, ok = routeScopes.Lookup(http.MethodPost, "/dead-letters/{id}/redrive")
	require.True(t, ok)
	assert.Equal(t, []auth.Scope{auth.ScopeAlertsWrite}, scopes)
}
