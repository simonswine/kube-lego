package ingress

import (
	"testing"
	"time"

	"github.com/jetstack/kube-lego/pkg/kubelego_const"
	"github.com/jetstack/kube-lego/pkg/mocks"

	log "github.com/Sirupsen/logrus"
	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"k8s.io/client-go/kubernetes"
	k8sExtensions "k8s.io/client-go/pkg/apis/extensions/v1beta1"
	"k8s.io/client-go/rest"
	"net/http"
	"net/http/httptest"
)

func TestTls(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Tls Suite")
}

var _ = Describe("Tls", func() {
	var (
		ctrlMock *gomock.Controller
		mockIng  *mocks.MockIngress
		mockKl   *mocks.MockKubeLego
		mockSec  *mocks.MockSecret
		tls      *Tls
	)

	BeforeEach(func() {
		ctrlMock = gomock.NewController(GinkgoT())
		defer ctrlMock.Finish()

		tls = &Tls{
			IngressTLS: &k8sExtensions.IngressTLS{
				Hosts:      []string{"das.de.de", "k8s.io"},
				SecretName: "my-secret",
			},
		}

		mockKl = mocks.DummyKubeLego(ctrlMock)
		mockIng = mocks.DummyIngressDomain1(ctrlMock, []kubelego.Tls{tls})
		mockSec = mocks.DummySecret(ctrlMock, time.Now(), []string{"das.de.de"})

		tls.ingress = mockIng
	})

	Describe("Secret", func() {
		Context("when called for the first time", func() {
			It("should initialize a new secret object and set it in tls", func() {
				ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					http.Error(w, "not found", 404)
				}))
				defer ts.Close()
				localConfig := &rest.Config{Host: ts.URL}
				kubeClient, _ := kubernetes.NewForConfig(localConfig)
				mockKl.EXPECT().KubeClient().AnyTimes().Return(kubeClient)
				mockIng.EXPECT().KubeLego().AnyTimes().Return(mockKl)

				secret := tls.Secret()

				Expect(secret).NotTo(BeNil())
				Expect(tls.secret).NotTo(BeNil())
				Expect(tls.secret).To(Equal(secret))
				Expect(secret.Exists()).To(Equal(false))
			})
		})

		Context("when a secret object already initialized", func() {
			It("should return already initialized secret object", func() {
				tls.secret = mockSec
				Expect(tls.Secret()).To(Equal(mockSec))
			})
		})
	})

	Describe("newCertNeeded", func() {
		Context("Tls with matching certificate", func() {
			BeforeEach(func() {
				mockKl.EXPECT().LegoMinimumValidity().AnyTimes().Return(
					20 * 24 * time.Hour,
				)

				mockIng.EXPECT().KubeLego().AnyTimes().Return(mockKl)
				mockIng.EXPECT().Log().AnyTimes().Return(log.WithField("context", "ingress"))
				tls.secret = mockSec
				mockSec.EXPECT().Exists().AnyTimes().Return(true)
				mockSec.EXPECT().TlsDomainsInclude(
					[]string{"das.de.de", "k8s.io"},
				).AnyTimes().Return(true)

			})
			It("should be true for expired", func() {
				mockSec.EXPECT().TlsExpireTime().AnyTimes().Return(
					time.Now().Add(-time.Minute),
					nil,
				)
				Expect(
					tls.newCertNeeded(),
				).To(Equal(true))
			})
			It("should be true for validity below minimum validity", func() {
				mockSec.EXPECT().TlsExpireTime().AnyTimes().Return(
					time.Now().Add(48*time.Hour),
					nil,
				)
				Expect(
					tls.newCertNeeded(),
				).To(Equal(true))
			})
			It("should be false for unexpired cert", func() {
				mockSec.EXPECT().TlsExpireTime().AnyTimes().Return(
					time.Now().Add(30*24*time.Hour),
					nil,
				)
				Expect(
					tls.newCertNeeded(),
				).To(Equal(false))
			})
		})
	})
})
