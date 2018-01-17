package kubelego

import (
	"github.com/jetstack/kube-lego/pkg/kubelego_const"
	"os"
	"testing"
)

func TestKubeLego_LegoUrl(t *testing.T) {
	kl := New("")
	os.Setenv("LEGO_EMAIL", "test@example.com")
	os.Setenv("LEGO_POD_IP", "10.0.0.1")

	kl.paramsLego()
	if len(kl.LegoURL()) == 0 {
		t.Error("LegoUrl must not be empty when not set")
	}

	testurl := "http://example.com/acme"
	os.Setenv("LEGO_URL", testurl)
	kl.paramsLego()
	if kl.legoURL != testurl {
		t.Error("LegoUrl was not set correctly")
	}

	testurlWithTrailingSlash := testurl + "/"
	os.Setenv("LEGO_URL", testurlWithTrailingSlash)
	kl.paramsLego()
	if kl.legoURL != testurl {
		t.Error("Trailing slash was not removed from LegoUrl ")
	}
}

func TestKubeLego_RsaKeySize(t *testing.T) {
	kl := New("")
	os.Setenv("LEGO_EMAIL", "test@example.com")
	os.Setenv("LEGO_POD_IP", "10.0.0.1")

	kl.paramsLego()
	if kl.LegoRsaKeySize() != kubelego.DefaultRsaKeySize {
		t.Error("LegoRsaKeySize default value not set")
	}

	os.Setenv("LEGO_RSA_KEYSIZE", "abc")
	if err := kl.paramsLego(); err == nil {
		t.Error("invalid LegoRsaKeySize was accepted")
	}

	os.Setenv("LEGO_RSA_KEYSIZE", "511")
	if err := kl.paramsLego(); err == nil {
		t.Error("invalid LegoRsaKeySize was accepted")
	}

	os.Setenv("LEGO_RSA_KEYSIZE", "512")
	kl.paramsLego()
	if kl.LegoRsaKeySize() != 512 {
		t.Error("LegoRsaKeySize not set correctly")
	}

	os.Setenv("LEGO_RSA_KEYSIZE", "4096")
	kl.paramsLego()
	if kl.LegoRsaKeySize() != 4096 {
		t.Error("LegoRsaKeySize not set correctly")
	}

}

func TestKubeLego_ExponentialBackoff(t *testing.T) {
	kl := New("")
	os.Setenv("LEGO_EMAIL", "test@example.com")
	os.Setenv("LEGO_POD_IP", "10.0.0.1")

	kl.paramsLego()
	if act, exp := kl.ExponentialBackoffMaxElapsedTime().Minutes(), 5.0; act != exp {
		t.Errorf("unexpected default MAX_ELAPSED_TIME, exp=%f act=%f", exp, act)
	}
	if act, exp := kl.ExponentialBackoffInitialInterval().Seconds(), 30.0; act != exp {
		t.Errorf("unexpected default INITIAL_INTERVAL, exp=%f act=%f", exp, act)
	}
	if act, exp := kl.ExponentialBackoffMultiplier(), 2.0; act != exp {
		t.Errorf("unexpected default MULTIPLIER, exp=%f act=%f", exp, act)
	}

	// max elapsed time
	os.Setenv("LEGO_EXPONENTIAL_BACKOFF_MAX_ELAPSED_TIME", "abc")
	if err := kl.paramsLego(); err == nil {
		t.Errorf("expected an error for invalid MAX_ELAPSED_TIME")
	}

	os.Setenv("LEGO_EXPONENTIAL_BACKOFF_MAX_ELAPSED_TIME", "60s")
	if err := kl.paramsLego(); err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	if act, exp := kl.ExponentialBackoffMaxElapsedTime().Minutes(), 1.0; act != exp {
		t.Errorf("unexpected MAX_ELAPSED_TIME, exp=%f act=%f", exp, act)
	}

	// initial interval
	os.Setenv("LEGO_EXPONENTIAL_BACKOFF_INITIAL_INTERVAL", "abc")
	if err := kl.paramsLego(); err == nil {
		t.Errorf("expected an error for invalid INITIAL_INTERVAL")
	}

	os.Setenv("LEGO_EXPONENTIAL_BACKOFF_INITIAL_INTERVAL", "15s")
	if err := kl.paramsLego(); err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	if act, exp := kl.ExponentialBackoffInitialInterval().Seconds(), 15.0; act != exp {
		t.Errorf("unexpected INITIAL_INTERVAL, exp=%f act=%f", exp, act)
	}

	// multiplier
	os.Setenv("LEGO_EXPONENTIAL_BACKOFF_MULTIPLIER", "abc")
	if err := kl.paramsLego(); err == nil {
		t.Errorf("expected an error for invalid MULTIPLIER")
	}

	os.Setenv("LEGO_EXPONENTIAL_BACKOFF_MULTIPLIER", "1.1")
	if err := kl.paramsLego(); err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	if act, exp := kl.ExponentialBackoffMultiplier(), 1.1; act != exp {
		t.Errorf("unexpected MULTIPLIER, exp=%f act=%f", exp, act)
	}

	os.Setenv("LEGO_EXPONENTIAL_BACKOFF_MULTIPLIER", "3")
	if err := kl.paramsLego(); err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	if act, exp := kl.ExponentialBackoffMultiplier(), 3.0; act != exp {
		t.Errorf("unexpected MULTIPLIER, exp=%f act=%f", exp, act)
	}

}
