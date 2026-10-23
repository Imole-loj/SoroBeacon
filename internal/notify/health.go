package notify

import (
	"errors"
	"net/http"
	"net/textproto"
	"time"

	"github.com/sorotrail/sorobeacon/internal/store"
)

// TestHealthUpdate maps the outcome of a "send test" click onto the health
// update that records it, so the API and the dashboard report the same thing
// about the same button.
//
// A test send is a real delivery outcome — that is what makes it useful for
// checking a channel you have just fixed — but the update deliberately carries
// no DisableAfter: the auto-disable threshold belongs to real alert
// deliveries, and a diagnostic click must never be what switches an
// operator's alerting off.
func TestHealthUpdate(sendErr error, at time.Time) store.ChannelHealthUpdate {
	u := store.ChannelHealthUpdate{At: at}
	if sendErr == nil {
		u.Success = true
		return u
	}
	u.Error = sanitizeDeliveryError(redactURLError(sendErr)).Error()
	u.Permanent = IsPermanent(sendErr)
	return u
}

// IsPermanent reports whether err is a failure the channel will not recover
// from on its own, as opposed to one that heals by itself.
//
// The distinction exists because auto-disabling a channel is a destructive
// answer to a temporary problem. A revoked bot token (401), a webhook the
// operator deleted (403) or a URL that no longer exists (404) fails the same
// way on every alert forever — that is the case auto-disable is for. A 5xx, a
// 429 or a timeout is the provider being briefly unavailable, and taking the
// channel out of rotation for it would turn a short outage into silently lost
// alerts, which is a worse outcome than the failure it was meant to fix. Only
// permanent failures therefore move a channel toward auto-disable; transient
// ones are still counted and reported, just not held against it.
//
// Anything unrecognised is transient, deliberately: health tracking should
// never disable a channel on a failure it does not understand.
func IsPermanent(err error) bool {
	if err == nil {
		return false
	}
	// Both status-carrying error types have to be recognised: the shared
	// request helpers in http.go return *StatusError, while the channels
	// that build their own requests return *HTTPStatusError. Matching only
	// one of them would leave auto-disable inert for half the channel types.
	var httpErr *HTTPStatusError
	if errors.As(err, &httpErr) {
		return permanentStatus(httpErr.StatusCode)
	}
	var statusErr *StatusError
	if errors.As(err, &statusErr) {
		return permanentStatus(statusErr.Code)
	}
	// A rotated SMTP password or a rejected sender fails the email channel
	// the same way a revoked token fails a webhook, and net/smtp reports it
	// as a 5xx reply (535 is the authentication failure every operator hits).
	var smtpErr *textproto.Error
	if errors.As(err, &smtpErr) {
		return smtpErr.Code >= 500
	}
	return false
}

// permanentStatus reports whether an HTTP status means the channel will not
// recover on its own: a revoked credential (401), a destination that refuses
// this sender (403), or a webhook that no longer exists (404). Everything
// else — 5xx, 429, a timeout — is the provider having a bad day.
func permanentStatus(code int) bool {
	switch code {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
		return true
	}
	return false
}

// Retryable reports whether another delivery attempt could plausibly succeed.
//
// It is a different question from IsPermanent, and the difference matters. A
// 400 is the receiver saying "this request is wrong": it says nothing about
// the channel's health — it is our payload, not its credential — but sending
// the same request again fails the same way. Retrying it three times buys
// nothing and fills the delivery history with identical failures.
//
// The exception is the 4xx that asks the client to come back later: 408, 425
// and 429 are the receiver saying "not now", and those are worth another
// attempt. Everything else — a 5xx, a timeout, a transport error — is
// transient as well.
//
// Anything unrecognised is retryable, deliberately: an unknown failure is
// more likely to be a bad moment than a verdict.
func Retryable(err error) bool {
	if err == nil {
		return true
	}
	// Both status-carrying error types have to be recognised, for the same
	// reason IsPermanent recognises both: the shared request helpers return
	// *StatusError and the channels that build their own return
	// *HTTPStatusError.
	var httpErr *HTTPStatusError
	if errors.As(err, &httpErr) {
		return retryableStatus(httpErr.StatusCode)
	}
	var statusErr *StatusError
	if errors.As(err, &statusErr) {
		return retryableStatus(statusErr.Code)
	}
	return true
}

// retryableStatus reports whether an HTTP status leaves room for another
// attempt. A 4xx that is not a "come back later" answer is the receiver
// rejecting the request itself, and repeating it unchanged changes nothing.
func retryableStatus(code int) bool {
	if code < 400 || code > 499 {
		return true
	}
	switch code {
	case http.StatusRequestTimeout, http.StatusTooEarly, http.StatusTooManyRequests:
		return true
	}
	return false
}
