package ingress

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jetstack/kube-lego/pkg/kubelego_const"
	"github.com/jetstack/kube-lego/pkg/secret"
	"github.com/jetstack/kube-lego/pkg/utils"

	"github.com/Sirupsen/logrus"
	k8sApi "k8s.io/client-go/pkg/api/v1"
	k8sExtensions "k8s.io/client-go/pkg/apis/extensions/v1beta1"
)

var _ kubelego.Tls = &Tls{}

type Tls struct {
	namespace  string
	name       string
	secretName string
	hosts      []string
	kl         kubelego.KubeLego
	secret     kubelego.Secret
	logger     func() *logrus.Entry
}

func NewTls(ingtls *k8sExtensions.IngressTLS, ing kubelego.Ingress) *Tls {
	t := Tls{
		secretName: ingtls.SecretName,
		hosts:      utils.StringSliceLowerCase(ingtls.Hosts),
		kl:         ing.KubeLego(),
		logger:     ing.Log,
	}

	if ing.Object() != nil {
		t.namespace = ing.Object().Namespace
		t.name = ing.Object().Name
	}

	return &t
}

func (t *Tls) Validate() error {
	if len(t.Hosts()) == 0 {
		return fmt.Errorf("No hosts specified")
	}

	if t.secretName == "" {
		return fmt.Errorf("No secret name specified")
	}
	return nil
}

func (t *Tls) SecretMetadata() (meta *k8sApi.ObjectMeta) {
	return &k8sApi.ObjectMeta{
		Namespace: t.namespace,
		Name:      t.secretName,
	}
}

func (t *Tls) IngressMetadata() (meta *k8sApi.ObjectMeta) {
	return &k8sApi.ObjectMeta{
		Namespace: t.namespace,
		Name:      t.name,
	}
}

func (t *Tls) Secret() kubelego.Secret {
	if t.secret != nil {
		return t.secret
	}
	t.secret = secret.New(t.kl, t.namespace, t.secretName)
	return t.secret
}

func (t *Tls) Hosts() []string {
	return t.hosts
}

func (t *Tls) Log() *logrus.Entry {
	return t.logger().WithField("context", "ingress_tls")
}

func (i *Tls) newCertNeeded() bool {
	if len(i.hosts) == 0 {
		i.Log().Info("no host associated with ingress")
		return false
	}

	tlsSecret := i.Secret()
	if !tlsSecret.Exists() {
		i.Log().Info("no cert associated with ingress")
		return true
	}

	if !tlsSecret.TlsDomainsInclude(i.hosts) {
		i.Log().WithField("domains", i.hosts).Info("cert does not cover all domains")
		return true
	}

	expireTime, err := tlsSecret.TlsExpireTime()
	if err != nil {
		i.Log().Warn("error while reading expiry time: ", err)
		return true
	}

	minimumValidity := i.kl.LegoMinimumValidity()
	timeLeft := time.Until(expireTime)
	logger := i.Log().WithField("expire_time", expireTime)
	if timeLeft < minimumValidity {
		logger.Infof("cert expires soon so renew")
		return true
	}

	logger.Infof("cert expires in %.1f days, no renewal needed", timeLeft.Hours()/24)
	return false
}

func (t *Tls) Process() error {

	if !t.newCertNeeded() {
		t.Log().Infof("no cert request needed")
		return nil
	}

	return t.RequestCert()
}

func (t *Tls) RequestCert() error {
	// sanity check
	if t.secretName == "" {
		return errors.New("Ingress has an empty secretName. Skipping certificate retrieval")
	}

	t.Log().Infof("requesting certificate for %s", strings.Join(t.Hosts(), ","))

	certData, err := t.kl.AcmeClient().ObtainCertificate(
		t.Hosts(),
	)
	if err != nil {
		return err
	}

	s := t.Secret()
	s.Object().Annotations = map[string]string{
		kubelego.AnnotationEnabled: "true",
	}
	s.Object().Type = k8sApi.SecretTypeTLS

	s.Object().Data = certData

	return s.Save()
}
