package api

import (
	"testing"
	"time"
)

func TestRegistrationCurrent(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	if !RegistrationCurrent(0, now) {
		t.Fatal("an entry with no expiry was refused")
	}
	if RegistrationCurrent(now.Unix(), now) {
		t.Fatal("an entry was authorized at its expiry second")
	}
	if RegistrationCurrent(now.Unix()-1, now) {
		t.Fatal("an expired entry was authorized")
	}
	if !RegistrationCurrent(now.Unix()+1, now) {
		t.Fatal("an entry one second before expiry was refused")
	}
}
