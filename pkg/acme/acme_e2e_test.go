package acme

import (
	b64 "encoding/base64"
	"errors"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"testing"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/golang/mock/gomock"
	"github.com/jetstack/kube-lego/pkg/kubelego_const"
	"github.com/jetstack/kube-lego/pkg/mocks"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/acme"
	"golang.org/x/net/context"
	"k8s.io/apimachinery/pkg/util/intstr"
)

var log = logrus.WithField("context", "test-mock")
var cmdNgrok *exec.Cmd
var domain string

func TestMain(m *testing.M) {
	logrus.SetLevel(logrus.DebugLevel)
	setupNgrok()
	defer cmdNgrok.Process.Kill()
	domain = getDomain()

	os.Exit(m.Run())
}

func setupMockedKubeLego(t *testing.T) (*mocks.MockKubeLego, *gomock.Controller) {
	ctrl := gomock.NewController(t)

	mockKL := mocks.NewMockKubeLego(ctrl)
	mockKL.EXPECT().Log().AnyTimes().Return(log)
	mockKL.EXPECT().Version().AnyTimes().Return("mocked-version")
	mockKL.EXPECT().LegoHTTPPort().AnyTimes().Return(intstr.FromInt(8181))
	mockKL.EXPECT().AcmeUser().MinTimes(1).Return(nil, errors.New("I am only mocked"))
	mockKL.EXPECT().LegoURL().MinTimes(1).Return("https://acme-staging.api.letsencrypt.org/directory")
	mockKL.EXPECT().LegoEmail().MinTimes(1).Return("kube-lego-e2e@example.com")
	mockKL.EXPECT().SaveAcmeUser(gomock.Any()).MinTimes(1).Return(nil)
	mockKL.EXPECT().LegoRsaKeySize().AnyTimes().Return(2048)
	mockKL.EXPECT().ExponentialBackoffMaxElapsedTime().MinTimes(1).Return(time.Minute * 5)
	mockKL.EXPECT().ExponentialBackoffInitialInterval().MinTimes(1).Return(time.Second * 30)
	mockKL.EXPECT().ExponentialBackoffMultiplier().MinTimes(1).Return(2.0)

	return mockKL, ctrl
}

func setupNgrok() {
	command := []string{"ngrok", "http", "--bind-tls", "false", "8181"}
	cmdNgrok = exec.Command(command[0], command[1:]...)
	err := cmdNgrok.Start()
	if err != nil {
		log.Fatal("failed to start ngrok", err)
	}
}

func getDomain() string {
	regexDomain := regexp.MustCompile("http://([a-z0-9]+.\\.ngrok\\.io)")
	var domain string
	for {
		time.Sleep(100 * time.Millisecond)
		resp, err := http.Get("http://localhost:4040/status")
		if err != nil {
			log.Warn(err)
			continue
		}
		defer resp.Body.Close()

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Warn(err)
			continue
		}

		matched := regexDomain.FindStringSubmatch(string(body))
		if matched == nil {
			continue
		}

		domain = matched[1]
		log.Infof("kube-lego domain is %s", domain)

		break
	}

	return domain
}

func setupAndStartAcmeServer(t *testing.T, action func(*mocks.MockKubeLego, *Acme, string)) {
	mockKL, mockCtrl := setupMockedKubeLego(t)
	defer mockCtrl.Finish()

	stopCh := make(chan struct{})
	a := New(mockKL)
	go a.RunServer(stopCh)

	action(mockKL, a, domain)

	close(stopCh)
	time.Sleep(100 * time.Millisecond)
}

func createUserData(t *testing.T, mockKL *mocks.MockKubeLego, a *Acme) map[string][]byte {
	mockKL.EXPECT().LegoURL().MinTimes(1).Return("https://acme-staging.api.letsencrypt.org/directory")
	mockKL.EXPECT().LegoEmail().MinTimes(1).Return("kube-lego-e2e@example.com")

	privateKeyPem, privateKey, err := a.generatePrivateKey()
	assert.Nil(t, err)

	client := &acme.Client{
		Key:          privateKey,
		DirectoryURL: a.kubelego.LegoURL(),
	}

	account := &acme.Account{
		Contact: a.getContact(),
	}

	account, err = client.Register(
		context.Background(),
		account,
		a.acceptTos,
	)
	assert.Nil(t, err)

	return map[string][]byte{
		kubelego.AcmePrivateKey:      privateKeyPem,
		kubelego.AcmeRegistrationUrl: []byte(account.URI),
	}
}

func TestAcme_E2E(t *testing.T) {
	setupAndStartAcmeServer(t, func(mockKL *mocks.MockKubeLego, a *Acme, domain string) {
		mockKL.EXPECT().AcmeUser().MinTimes(1).Return(nil, errors.New("I am only mocked"))
		mockKL.EXPECT().LegoURL().MinTimes(1).Return("https://acme-staging.api.letsencrypt.org/directory")
		mockKL.EXPECT().LegoEmail().MinTimes(1).Return("kube-lego-e2e@example.com")
		mockKL.EXPECT().SaveAcmeUser(gomock.Any()).MinTimes(1).Return(nil)

		a.ObtainCertificate([]string{domain})
	})
}

func TestAcme_ObtainCertificateWithExistingAcmeUser(t *testing.T) {
	setupAndStartAcmeServer(t, func(mockKL *mocks.MockKubeLego, a *Acme, domain string) {
		userData := createUserData(t, mockKL, a)

		mockKL.EXPECT().AcmeUser().MinTimes(1).Return(userData, nil)

		a.ObtainCertificate([]string{domain})
	})
}

func TestAcme_ObtainCertificateWithIncorrectUserData(t *testing.T) {
	setupAndStartAcmeServer(t, func(mockKL *mocks.MockKubeLego, a *Acme, domain string) {
		userData := createUserData(t, mockKL, a)
		userData[kubelego.AcmePrivateKey] = []byte(b64.StdEncoding.EncodeToString(userData[kubelego.AcmePrivateKey]))

		mockKL.EXPECT().AcmeUser().MinTimes(1).Return(userData, nil)
		mockKL.EXPECT().SaveAcmeUser(gomock.Any()).MinTimes(1).Return(nil)

		a.ObtainCertificate([]string{domain})
	})
}
