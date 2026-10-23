package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sorotrail/sorobeacon/internal/store"
)

// errStoreDown stands in for a database that is not there.
var errStoreDown = errors.New("store down")

type templateStore struct {
	fakeStore
	templates []store.MonitorTemplate
	nextID    int64
	monitors  []store.Monitor
	monNextID int64
	rules     []store.Rule
	channels  map[int64][]int64
	// known are the channels this workspace has, so a template that attaches
	// to a channel that does not exist can be tested.
	known []store.Channel
	// createErr makes the write fail, standing in for a store error, so a
	// test can check that a failed instantiation leaves nothing behind.
	createErr error
}

func (t *templateStore) CreateMonitorTemplate(_ context.Context, tmpl *store.MonitorTemplate) error {
	t.nextID++
	tmpl.ID = t.nextID
	t.templates = append(t.templates, *tmpl)
	return nil
}

func (t *templateStore) GetMonitorTemplate(_ context.Context, id int64) (*store.MonitorTemplate, error) {
	for _, tmpl := range t.templates {
		if tmpl.ID == id {
			return &tmpl, nil
		}
	}
	return nil, store.ErrNotFound
}

func (t *templateStore) ListMonitorTemplates(_ context.Context) ([]store.MonitorTemplate, error) {
	return t.templates, nil
}

func (t *templateStore) UpdateMonitorTemplate(_ context.Context, tmpl *store.MonitorTemplate) error {
	for i, existing := range t.templates {
		if existing.ID == tmpl.ID {
			t.templates[i] = *tmpl
			return nil
		}
	}
	return store.ErrNotFound
}

func (t *templateStore) DeleteMonitorTemplate(_ context.Context, id int64) error {
	for i, tmpl := range t.templates {
		if tmpl.ID == id {
			t.templates = append(t.templates[:i], t.templates[i+1:]...)
			return nil
		}
	}
	return store.ErrNotFound
}

// CreateMonitorWithRules records the monitor, its rules and its channel
// links the way the store does: one call, all of it or none of it.
func (t *templateStore) CreateMonitorWithRules(_ context.Context, m *store.Monitor, rules []*store.Rule, channelIDs []int64) error {
	if t.createErr != nil {
		return t.createErr
	}
	t.monNextID++
	m.ID = t.monNextID
	t.monitors = append(t.monitors, *m)
	for _, r := range rules {
		r.ID = int64(len(t.rules) + 1)
		r.MonitorID = m.ID
		t.rules = append(t.rules, *r)
	}
	if len(channelIDs) > 0 {
		if t.channels == nil {
			t.channels = make(map[int64][]int64)
		}
		t.channels[m.ID] = channelIDs
	}
	return nil
}

func (t *templateStore) ListChannels(_ context.Context, _ bool) ([]store.Channel, error) {
	return t.known, nil
}

// postTemplateJSON sends a JSON body to a template server and returns the
// response and its error envelope.
func postTemplateJSON(t *testing.T, url, body string) (*http.Response, errorEnvelope) {
	t.Helper()
	res, err := http.Post(url, "application/json", bytes.NewBufferString(body))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { res.Body.Close() })
	raw, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	var env errorEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("decode response: %v\nbody: %s", err, raw)
	}
	return res, env
}

// detailReason returns the reason the envelope gives for one field.
func detailReason(env errorEnvelope, field string) (string, bool) {
	for _, d := range env.Details {
		if d.Field == field {
			return d.Reason, true
		}
	}
	return "", false
}

func TestCreateTemplate(t *testing.T) {
	st := &templateStore{}
	srv := httptest.NewServer(newProbeServer(st, &fakeRPC{}))
	defer srv.Close()

	body := `{"name":"token watcher","description":"watches token events","rules":[{"type":"token_event","params":{"event":"transfer"}}],"channel_ids":[1],"parameters":[{"name":"contract","required":true}]}`
	res, err := http.Post(srv.URL+"/templates", "application/json", bytes.NewBufferString(body))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201", res.StatusCode)
	}
	if len(st.templates) != 1 {
		t.Fatalf("expected 1 template, got %d", len(st.templates))
	}
	if st.templates[0].Name != "token watcher" {
		t.Errorf("name = %q, want token watcher", st.templates[0].Name)
	}
}

func TestCreateTemplateValidation(t *testing.T) {
	st := &templateStore{}
	srv := httptest.NewServer(newProbeServer(st, &fakeRPC{}))
	defer srv.Close()

	res, err := http.Post(srv.URL+"/templates", "application/json", bytes.NewBufferString(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", res.StatusCode)
	}
}

// TestCreateTemplateRejectsUnknownRuleType: a template with a rule type the
// registry does not know is rejected when it is created, not silently at
// every instantiation.
func TestCreateTemplateRejectsUnknownRuleType(t *testing.T) {
	st := &templateStore{}
	srv := httptest.NewServer(newProbeServer(st, &fakeRPC{}))
	defer srv.Close()

	res, env := postTemplateJSON(t, srv.URL+"/templates",
		`{"name":"broken","rules":[{"type":"not_a_rule","params":{}}]}`)
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %v", res.StatusCode, env)
	}
	if reason, ok := detailReason(env, "rules[0].type"); !ok || reason != "unknown rule type" {
		t.Errorf("details = %+v, want rules[0].type to name the unknown rule type", env.Details)
	}
	if len(st.templates) != 0 {
		t.Errorf("a rejected template was stored: %+v", st.templates)
	}
}

// TestCreateTemplateRejectsInvalidParams: the parts of a rule's params that
// do not depend on substitution are checked when the template is written.
func TestCreateTemplateRejectsInvalidParams(t *testing.T) {
	st := &templateStore{}
	srv := httptest.NewServer(newProbeServer(st, &fakeRPC{}))
	defer srv.Close()

	res, env := postTemplateJSON(t, srv.URL+"/templates",
		`{"name":"broken","rules":[{"type":"value_threshold","params":{"comparison":"nope","threshold":1}}]}`)
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %v", res.StatusCode, env)
	}
	if _, ok := detailReason(env, "rules[0].params.comparison"); !ok {
		t.Errorf("details = %+v, want the bad comparison to be named", env.Details)
	}
	if len(st.templates) != 0 {
		t.Errorf("a rejected template was stored: %+v", st.templates)
	}
}

// TestCreateTemplateAcceptsSubstitutedParams: a rule whose value comes from
// a parameter cannot be judged before the template is instantiated, so it is
// not rejected here.
func TestCreateTemplateAcceptsSubstitutedParams(t *testing.T) {
	st := &templateStore{}
	srv := httptest.NewServer(newProbeServer(st, &fakeRPC{}))
	defer srv.Close()

	res, env := postTemplateJSON(t, srv.URL+"/templates",
		`{"name":"templated","rules":[{"type":"value_threshold","params":{"comparison":"gt","threshold":"{{threshold}}"}}],`+
			`"parameters":[{"name":"threshold","required":true}]}`)
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %v", res.StatusCode, env)
	}
	if len(st.templates) != 1 {
		t.Errorf("expected 1 template, got %d", len(st.templates))
	}
}

// TestUpdateTemplateRejectsUnknownRuleType: the same check on update.
func TestUpdateTemplateRejectsUnknownRuleType(t *testing.T) {
	st := &templateStore{templates: []store.MonitorTemplate{{ID: 1, Name: "t"}}, nextID: 1}
	srv := httptest.NewServer(newProbeServer(st, &fakeRPC{}))
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodPatch, srv.URL+"/templates/1",
		bytes.NewBufferString(`{"rules":[{"type":"not_a_rule","params":{}}]}`))
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", res.StatusCode)
	}
	if len(st.templates[0].Rules) != 0 {
		t.Errorf("the rejected rules were stored: %+v", st.templates[0].Rules)
	}
}

func TestInstantiateTemplate(t *testing.T) {
	st := &templateStore{
		templates: []store.MonitorTemplate{
			{
				ID:         1,
				Name:       "token watcher",
				Rules:      []store.MonitorTemplateRule{{Type: "token_event", Params: json.RawMessage(`{"event":"transfer"}`)}},
				ChannelIDs: []int64{1},
				Parameters: []store.TemplateParameter{{Name: "contract", Required: true}},
			},
		},
		nextID: 1,
		known:  []store.Channel{{ID: 1, Name: "ops"}},
	}
	srv := httptest.NewServer(newProbeServer(st, &fakeRPC{}))
	defer srv.Close()

	body := `{"name":"my watcher","contract_ids":["CABCDEF"],"parameters":{"contract":"CABCDEF"}}`
	res, err := http.Post(srv.URL+"/templates/1/instantiate", "application/json", bytes.NewBufferString(body))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201", res.StatusCode)
	}
	if len(st.monitors) != 1 {
		t.Fatalf("expected 1 monitor, got %d", len(st.monitors))
	}
	// The monitor comes back with the rules and the channel links it was
	// created with, not as a bare monitor.
	if len(st.rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(st.rules))
	}
	if st.rules[0].Type != "token_event" {
		t.Errorf("rule type = %q, want token_event", st.rules[0].Type)
	}
	if got := st.channels[st.monitors[0].ID]; len(got) != 1 || got[0] != 1 {
		t.Errorf("channel links = %v, want [1]", got)
	}
}

// TestInstantiateTemplateMissingParam: a required parameter with no value is
// reported. It used to be a 400 with the same wording, so only the status
// changed: the request was understood, and what it carries cannot produce a
// valid monitor.
func TestInstantiateTemplateMissingParam(t *testing.T) {
	st := &templateStore{
		templates: []store.MonitorTemplate{
			{
				ID:         1,
				Name:       "token watcher",
				Parameters: []store.TemplateParameter{{Name: "contract", Required: true}},
			},
		},
		nextID: 1,
	}
	srv := httptest.NewServer(newProbeServer(st, &fakeRPC{}))
	defer srv.Close()

	body := `{"name":"my watcher","contract_ids":["CABCDEF"],"parameters":{}}`
	res, env := postTemplateJSON(t, srv.URL+"/templates/1/instantiate", body)
	if res.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422: %v", res.StatusCode, env)
	}
	if reason, ok := detailReason(env, "parameters.contract"); !ok || reason != "required parameter" {
		t.Errorf("details = %+v, want the missing parameter to be named", env.Details)
	}
	if len(st.monitors) != 0 {
		t.Errorf("a rejected instantiation created %d monitors", len(st.monitors))
	}
}

// TestInstantiateTemplateUnknownParameter: a parameter name the template
// does not declare is a typo, and it used to leave the placeholder
// unsubstituted so the rule it belonged to silently vanished.
func TestInstantiateTemplateUnknownParameter(t *testing.T) {
	st := &templateStore{
		templates: []store.MonitorTemplate{
			{
				ID:         1,
				Name:       "token watcher",
				Rules:      []store.MonitorTemplateRule{{Type: "token_event", Params: json.RawMessage(`{"event":"{{contract}}"}`)}},
				Parameters: []store.TemplateParameter{{Name: "contract", Required: true}},
			},
		},
		nextID: 1,
	}
	srv := httptest.NewServer(newProbeServer(st, &fakeRPC{}))
	defer srv.Close()

	body := `{"name":"my watcher","contract_ids":["CABCDEF"],"parameters":{"contractt":"CABCDEF"}}`
	res, env := postTemplateJSON(t, srv.URL+"/templates/1/instantiate", body)
	if res.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422: %v", res.StatusCode, env)
	}
	if _, ok := detailReason(env, "parameters.contractt"); !ok {
		t.Errorf("details = %+v, want the misspelled parameter to be named", env.Details)
	}
	if len(st.monitors) != 0 {
		t.Errorf("a rejected instantiation created %d monitors", len(st.monitors))
	}
	if len(st.rules) != 0 {
		t.Errorf("a rejected instantiation created %d rules", len(st.rules))
	}
}

// TestInstantiateTemplateRejectsInvalidRule: a rule whose params do not
// validate once the parameters are substituted is reported by its index in
// the template, and nothing is written.
func TestInstantiateTemplateRejectsInvalidRule(t *testing.T) {
	st := &templateStore{
		templates: []store.MonitorTemplate{
			{
				ID:   1,
				Name: "token watcher",
				Rules: []store.MonitorTemplateRule{
					{Type: "token_event", Params: json.RawMessage(`{"event":"transfer"}`)},
					{Type: "value_threshold", Params: json.RawMessage(`{"comparison":"gt","threshold":"{{threshold}}"}`)},
				},
				Parameters: []store.TemplateParameter{{Name: "threshold", Required: true}},
			},
		},
		nextID: 1,
	}
	srv := httptest.NewServer(newProbeServer(st, &fakeRPC{}))
	defer srv.Close()

	body := `{"name":"my watcher","contract_ids":["CABCDEF"],"parameters":{"threshold":"not a number"}}`
	res, env := postTemplateJSON(t, srv.URL+"/templates/1/instantiate", body)
	if res.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422: %v", res.StatusCode, env)
	}
	if _, ok := detailReason(env, "rules[1].params.threshold"); !ok {
		t.Errorf("details = %+v, want the second rule's threshold to be named", env.Details)
	}
	if len(st.monitors) != 0 {
		t.Errorf("a rejected instantiation created %d monitors", len(st.monitors))
	}
	if len(st.rules) != 0 {
		t.Errorf("a rejected instantiation created %d rules", len(st.rules))
	}
}

// TestInstantiateTemplateRejectsUnknownChannel: a channel that does not
// exist is reported instead of being dropped, which used to leave a monitor
// nobody hears from.
func TestInstantiateTemplateRejectsUnknownChannel(t *testing.T) {
	st := &templateStore{
		templates: []store.MonitorTemplate{
			{
				ID:         1,
				Name:       "token watcher",
				ChannelIDs: []int64{7},
			},
		},
		nextID: 1,
	}
	srv := httptest.NewServer(newProbeServer(st, &fakeRPC{}))
	defer srv.Close()

	body := `{"name":"my watcher","contract_ids":["CABCDEF"]}`
	res, env := postTemplateJSON(t, srv.URL+"/templates/1/instantiate", body)
	if res.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422: %v", res.StatusCode, env)
	}
	if reason, ok := detailReason(env, "channel_ids[0]"); !ok || reason != "channel not found" {
		t.Errorf("details = %+v, want the missing channel to be named", env.Details)
	}
	if len(st.monitors) != 0 {
		t.Errorf("a rejected instantiation created %d monitors", len(st.monitors))
	}
}

// TestInstantiateTemplateStoreFailureLeavesNothing: a store failure while
// writing answers 500 and leaves no monitor behind.
func TestInstantiateTemplateStoreFailureLeavesNothing(t *testing.T) {
	st := &templateStore{
		templates: []store.MonitorTemplate{{ID: 1, Name: "token watcher"}},
		nextID:    1,
		createErr: errStoreDown,
	}
	srv := httptest.NewServer(newProbeServer(st, &fakeRPC{}))
	defer srv.Close()

	body := `{"name":"my watcher","contract_ids":["CABCDEF"]}`
	res, err := http.Post(srv.URL+"/templates/1/instantiate", "application/json", bytes.NewBufferString(body))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", res.StatusCode)
	}
	if len(st.monitors) != 0 {
		t.Errorf("a failed instantiation created %d monitors", len(st.monitors))
	}
}

func TestDeleteTemplate(t *testing.T) {
	st := &templateStore{
		templates: []store.MonitorTemplate{{ID: 1, Name: "doomed"}},
		nextID:    1,
	}
	srv := httptest.NewServer(newProbeServer(st, &fakeRPC{}))
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/templates/1", nil)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", res.StatusCode)
	}
	if len(st.templates) != 0 {
		t.Fatalf("expected 0 templates, got %d", len(st.templates))
	}
}

func TestBulkInstantiateTemplate(t *testing.T) {
	st := &templateStore{
		templates: []store.MonitorTemplate{
			{
				ID:         1,
				Name:       "token watcher",
				Rules:      []store.MonitorTemplateRule{{Type: "token_event", Params: json.RawMessage(`{"event":"transfer"}`)}},
				ChannelIDs: []int64{1},
			},
		},
		nextID: 1,
		known:  []store.Channel{{ID: 1, Name: "ops"}},
	}
	srv := httptest.NewServer(newProbeServer(st, &fakeRPC{}))
	defer srv.Close()

	body := `{"instances":[{"name":"w1","contract_ids":["C1"]},{"name":"w2","contract_ids":["C2"]}]}`
	res, err := http.Post(srv.URL+"/templates/1/instantiate/bulk", "application/json", bytes.NewBufferString(body))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201", res.StatusCode)
	}
	if len(st.monitors) != 2 {
		t.Fatalf("expected 2 monitors, got %d", len(st.monitors))
	}
	if len(st.rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(st.rules))
	}
}

// TestBulkInstantiateTemplateValidatesEveryInstance: one bad instance fails
// the whole request, and nothing is written — the bulk handler validates
// everything before it writes anything.
func TestBulkInstantiateTemplateValidatesEveryInstance(t *testing.T) {
	st := &templateStore{
		templates: []store.MonitorTemplate{
			{
				ID:         1,
				Name:       "token watcher",
				Rules:      []store.MonitorTemplateRule{{Type: "token_event", Params: json.RawMessage(`{"event":"transfer"}`)}},
				ChannelIDs: []int64{1},
			},
		},
		nextID: 1,
		known:  []store.Channel{{ID: 1, Name: "ops"}},
	}
	srv := httptest.NewServer(newProbeServer(st, &fakeRPC{}))
	defer srv.Close()

	body := `{"instances":[{"name":"w1","contract_ids":["C1"]},{"name":"w2"}]}`
	res, env := postTemplateJSON(t, srv.URL+"/templates/1/instantiate/bulk", body)
	if res.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422: %v", res.StatusCode, env)
	}
	if _, ok := detailReason(env, "instances[1].contract_ids"); !ok {
		t.Errorf("details = %+v, want the second instance's problem to be named", env.Details)
	}
	if len(st.monitors) != 0 {
		t.Errorf("a rejected bulk instantiation created %d monitors", len(st.monitors))
	}
}
