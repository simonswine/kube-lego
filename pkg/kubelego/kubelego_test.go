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