package web

import (
	"encoding/json"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/sorotrail/sorobeacon/internal/reqid"
	"github.com/sorotrail/sorobeacon/internal/store"
)

// actor is who a dashboard mutation is recorded as. The dashboard session
// carries a role and a workspace but no name — there are no per-user
// accounts to name — so it is the request id: the same value audit() writes
// into the entry's Actor and the log line carries, which is what lets an
// operator tie an acknowledged alert back to the request that acknowledged
// it. The API's actor adds the credential's label when it has one; see
// internal/api/audit.go.
func actor(r *http.Request) string { return reqid.From(r) }

// audit records one append-only entry for a dashboard mutation. fields is the
// set of submitted field *names*; values are never passed here, because a
// channel form carries a webhook URL or token and the log must not hold it.
//
// A failed audit write is logged and never fails the request: the operator's
// change already happened and must not be rolled back over a bookkeeping
// error.
func (s *Server) audit(r *http.Request, action, targetType string, targetID int64, fields ...string) {
	diff := json.RawMessage(`{}`)
	if len(fields) > 0 {
		if b, err := json.Marshal(map[string]any{"fields": fields}); err == nil {
			diff = b
		}
	}
	entry := &store.AuditEntry{
		Actor:      reqid.From(r),
		Action:     action,
		TargetType: targetType,
		TargetID:   targetID,
		Diff:       diff,
	}
	if err := s.store.CreateAuditEntry(r.Context(), entry); err != nil {
		s.log.Error("write audit entry",
			"action", action, "target_type", targetType, "target_id", targetID, "err", err)
	}
}

// auditPageSize is how many entries one page of the audit page shows. Fixed
// rather than a query parameter: the page has one paging affordance (an Older
// link), and a size knob would have to travel with every cursor.
const auditPageSize = 50

// auditPage serves GET /audit: the append-only record of who changed what,
// newest first. It makes the same store call the API's listAudit makes, so
// the page and the API cannot drift into two different answers about the same
// rows — the API's job is the filtering and paging, and this handler only
// collects it.
//
// Admin only (the role table says so): the log names the credential behind
// every change, and the pages it links to — monitors, channels — are what
// someone would be reading it to answer questions about.
func (s *Server) auditPage(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.AuditFilter{Limit: auditPageSize}

	// An unknown entity type or cursor is dropped rather than rejected, the
	// way the alerts page treats an unknown severity: the page still lists
	// and the control shows what was actually applied. A target id that
	// cannot be read is different — it is an explicit filter that would
	// silently widen to the whole log — so it stops the listing and says so,
	// with the entered value kept in the box to be fixed in place.
	note := ""
	targetType := strings.TrimSpace(q.Get("target_type"))
	switch targetType {
	case "", "monitor", "rule", "channel", "alert":
		f.TargetType = targetType
	default:
		targetType = ""
	}
	targetIDInput := strings.TrimSpace(q.Get("target_id"))
	if targetIDInput != "" {
		id, err := strconv.ParseInt(targetIDInput, 10, 64)
		if err != nil || id < 1 {
			note = "That id could not be read. Enter a positive number, or clear the field."
		} else {
			f.TargetID = id
		}
	}
	f.Actor = strings.TrimSpace(q.Get("actor"))
	if v := q.Get("cursor"); v != "" {
		if id, err := strconv.ParseInt(v, 10, 64); err == nil && id >= 1 {
			f.AfterID = id
		} else if note == "" {
			note = "That cursor could not be read. Start the listing again from the first page."
		}
	}

	var entries []store.AuditEntry
	if note == "" {
		var err error
		entries, err = s.store.ListAuditEntries(r.Context(), f)
		if err != nil {
			s.fail(w, err)
			return
		}
	}
	data := map[string]any{
		"Title":      "Audit log",
		"Entries":    entries,
		"TargetType": targetType,
		"TargetID":   targetIDInput,
		"Actor":      f.Actor,
		"Note":       note,
		"HasFilters": targetType != "" || targetIDInput != "" || f.Actor != "",
	}
	if note == "" && len(entries) == f.Limit {
		last := entries[len(entries)-1]
		data["OlderHref"] = template.URL("/audit?" + auditFilterQuery(f) + "cursor=" + strconv.FormatInt(last.ID, 10))
	}
	s.render(w, r, "audit", data)
}

// auditFilterQuery is the filter prefix preserved on the Older paging link:
// every control that narrowed the first page has to narrow the next one, or
// paging quietly widens back to the whole log halfway through it.
func auditFilterQuery(f store.AuditFilter) string {
	v := url.Values{}
	if f.TargetType != "" {
		v.Set("target_type", f.TargetType)
	}
	if f.TargetID != 0 {
		v.Set("target_id", strconv.FormatInt(f.TargetID, 10))
	}
	if f.Actor != "" {
		v.Set("actor", f.Actor)
	}
	enc := v.Encode()
	if enc == "" {
		return ""
	}
	return enc + "&"
}

// auditFields renders the changed field names an audit diff recorded. The
// diff carries only names — values are dropped at write time because a
// channel config holds webhook URLs, bot tokens and SMTP credentials — so
// there is nothing here that can leak, and a diff that is not the expected
// shape renders as a dash rather than as raw JSON the page would then have
// to be trusted not to print.
func auditFields(diff json.RawMessage) string {
	var d struct {
		Fields []string `json:"fields"`
	}
	if len(diff) == 0 || json.Unmarshal(diff, &d) != nil {
		return "—"
	}
	if len(d.Fields) == 0 {
		return "—"
	}
	return strings.Join(d.Fields, ", ")
}
