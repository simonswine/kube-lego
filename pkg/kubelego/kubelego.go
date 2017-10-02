package kubelego

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jetstack/kube-lego/pkg/acme"
	"github.com/jetstack/kube-lego/pkg/ingress"
	kubelego "github.com/jetstack/kube-lego/pkg/kubelego_const"
	"github.com/jetstack/kube-lego/pkg/provider/gce"
	"github.com/jetstack/kube-lego/pkg/provider/nginx"
	"github.com/jetstack/kube-lego/pkg/secret"

	log "github.com/Sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	k8sApi "k8s.io/client-go/pkg/api/v1"
)

var _ kubelego.KubeLego = &KubeLego{}

func makeLog() *log.Entry {
	logtype := strings.ToLower(os.Getenv("LEGO_LOG_TYPE"))
	if logtype == "" {
		logtype = "text"
	}

	if logtype == "json" {
		log.SetFormatter(&log.JSONFormatter{})
	} else if logtype == "text" {
		log.SetFormatter(&log.TextFormatter{})
	} else {
		log.WithField("logtype", logtype).Fatal("Given logtype was not valid, check LEGO_LOG_TYPE configuration")
		os.Exit(1)
	}

	loglevel := strings.ToLower(os.Getenv("LEGO_LOG_LEVEL"))
	if len(loglevel) == 0 {
		log.SetLevel(log.InfoLevel)
	} else if loglevel == "debug" {
		log.SetLevel(log.DebugLevel)
	} else if loglevel == "info" {
		log.SetLevel(log.InfoLevel)
	} else if loglevel == "warn" {
		log.SetLevel(log.WarnLevel)
	} else if loglevel == "error" {
		log.SetLevel(log.ErrorLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}
	return log.WithField("context", "kubelego")
}

func New(version string) *KubeLego {
	return &KubeLego{
		version:   version,
		log:       makeLog(),
		stopCh:    make(chan struct{}),
		waitGroup: sync.WaitGroup{},
	}
}

func (kl *KubeLego) Log() *log.Entry {
	return kl.log
}

func (kl *KubeLego) Stop() {
	kl.Log().Info("shutting things down")
	close(kl.stopCh)
}

func (kl *KubeLego) IngressProvider(name string) (provider kubelego.IngressProvider, err error) {
	provider, ok := kl.ingressProvider[name]
	if !ok {
		return nil, fmt.Errorf("Ingress provider '%s' not found", name)
	}
	return
}

func (kl *KubeLego) Init() {
	kl.Log().Infof("kube-lego %s starting", kl.version)

	// handle sigterm correctly
	k := make(chan os.Signal, 1)
	signal.Notify(k, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		s := <-k
		logger := kl.Log().WithField("signal", s.String())
		logger.Debug("received signal")
		kl.Stop()
	}()

	// parse env vars
	err := kl.paramsLego()
	if err != nil {
		kl.Log().Fatal(err)
	}

	kl.ingressProvider = map[string]kubelego.IngressProvider{}
	for _, provider := range kl.supportedIngressProvider {
		switch provider {
		case "gce":
			kl.ingressProvider["gce"] = gce.New(kl)
			break
		case "nginx":
			kl.ingressProvider["nginx"] = nginx.New(kl)
			break
		default:
			kl.Log().Warnf("Unsupported provider [%s], please add a handler in kubelego.go#Init()", provider)
			break
		}
	}

	// start workers
	kl.WatchReconfigure()

	// intialize kube api
	err = kl.InitKube()
	if err != nil {
		kl.Log().Fatal(err)
	}

	// run acme http server
	myAcme := acme.New(kl)
	go func() {
		kl.waitGroup.Add(1)
		defer kl.waitGroup.Done()
		myAcme.RunServer(kl.stopCh)
	}()
	kl.acmeClient = myAcme

	// run ticker to check certificates periodically
	ticker := time.NewTicker(kl.checkInterval)
	go func() {
		for timestamp := range ticker.C {
			kl.Log().Infof("Periodically check certificates at %s", timestamp)
			kl.requestReconfigure()
		}
	}()

	// watch for ingress controller events
	kl.WatchEvents()

	// wait for stop signal
	<-kl.stopCh
	ticker.Stop()
	kl.Log().Infof("exiting")
	kl.waitGroup.Wait()
}

func (kl *KubeLego) AcmeClient() kubelego.Acme {
	return kl.acmeClient
}

func (kl *KubeLego) KubeClient() *kubernetes.Clientset {
	return kl.kubeClient
}

func (kl *KubeLego) Version() string {
	return kl.version
}

func (kl *KubeLego) LegoHTTPPort() intstr.IntOrString {
	return kl.httpPort
}

func (kl *KubeLego) LegoURL() string {
	return kl.url
}

func (kl *KubeLego) LegoEmail() string {
	return kl.email
}

func (kl *KubeLego) LegoNamespace() string {
	return kl.namespace
}

func (kl *KubeLego) LegoWatchNamespace() string {
	return kl.watchNamespace
}

func (kl *KubeLego) LegoPodIP() net.IP {
	return kl.podIP
}

func (kl *KubeLego) LegoDefaultIngressClass() string {
	return kl.defaultIngressClass
}

func (kl *KubeLego) LegoIngressNameNginx() string {
	return kl.ingressNameNginx
}
func (kl *KubeLego) LegoSupportedIngressClass() []string {
	return kl.supportedIngressClass
}

func (kl *KubeLego) LegoSupportedIngressProvider() []string {
	return kl.supportedIngressProvider
}

func (kl *KubeLego) LegoServiceNameNginx() string {
	return kl.serviceNameNginx
}

func (kl *KubeLego) LegoServiceNameGce() string {
	return kl.serviceNameGCE
}

func (kl *KubeLego) LegoMinimumValidity() time.Duration {
	return kl.minimumValidity
}

func (kl *KubeLego) LegoCheckInterval() time.Duration {
	return kl.checkInterval
}

func (kl *KubeLego) LegoKubeApiURL() string {
	return kl.kubeAPIURL
}

func (kl *KubeLego) acmeSecret() *secret.Secret {
	return secret.New(kl, kl.LegoNamespace(), kl.secretName)
}

func (kl *KubeLego) AcmeUser() (map[string][]byte, error) {
	s := kl.acmeSecret()
	if !s.Exists() {
		return map[string][]byte{}, fmt.Errorf("no acme user found %s/%s", kl.LegoNamespace(), kl.secretName)
	}
	return s.SecretApi.Data, nil
}

func (kl *KubeLego) SaveAcmeUser(data map[string][]byte) error {
	s := kl.acmeSecret()
	s.SecretApi.Data = data
	return s.Save()
}

// read config parameters from ENV vars
func (kl *KubeLego) paramsLego() error {

	kl.email = os.Getenv("LEGO_EMAIL")
	if len(kl.email) == 0 {
		return errors.New("Please provide an email address for certificate expiration notifications in LEGO_EMAIL (https://letsencrypt.org/docs/expiration-emails/)")
	}

	kl.podIP = net.ParseIP(os.Getenv("LEGO_POD_IP"))
	if kl.podIP == nil {
		return errors.New("Please provide the pod's IP via environment variable LEGO_POD_IP using the downward API (http://kubernetes.io/docs/user-guide/downward-api/)")
	}

	kl.namespace = os.Getenv("LEGO_NAMESPACE")
	if len(kl.namespace) == 0 {
		kl.namespace = k8sApi.NamespaceDefault
	}

	kl.url = os.Getenv("LEGO_URL")
	if len(kl.url) == 0 {
		kl.url = "https://acme-staging.api.letsencrypt.org/directory"
	}

	kl.secretName = os.Getenv("LEGO_SECRET_NAME")
	if len(kl.secretName) == 0 {
		kl.secretName = "kube-lego-account"
	}

	kl.serviceNameNginx = os.Getenv("LEGO_SERVICE_NAME_NGINX")
	if len(kl.serviceNameNginx) == 0 {
		kl.serviceNameNginx = os.Getenv("LEGO_SERVICE_NAME")
		if len(kl.serviceNameNginx) == 0 {
			kl.serviceNameNginx = "kube-lego-nginx"
		}
	}

	kl.serviceNameGCE = os.Getenv("LEGO_SERVICE_NAME_GCE")
	if len(kl.serviceNameGCE) == 0 {
		kl.serviceNameGCE = "kube-lego-gce"
	}

	supportedProviders := os.Getenv("LEGO_SUPPORTED_INGRESS_PROVIDER")
	if len(supportedProviders) == 0 {
		kl.supportedIngressProvider = kubelego.SupportedIngressProviders
	} else {
		kl.supportedIngressProvider = strings.Split(supportedProviders, ",")
	}

	supportedIngressClass := os.Getenv("LEGO_SUPPORTED_INGRESS_CLASS")
	if len(supportedIngressClass) == 0 {
		kl.supportedIngressClass = kubelego.SupportedIngressClasses
	} else {
		kl.supportedIngressClass = strings.Split(supportedIngressClass, ",")
	}

	defaultIngressClass := os.Getenv("LEGO_DEFAULT_INGRESS_CLASS")
	if len(defaultIngressClass) == 0 {
		kl.defaultIngressClass = "nginx"
	} else {
		var err error = nil
		kl.defaultIngressClass, err = ingress.IsSupportedIngressClass(kl.supportedIngressClass, defaultIngressClass)
		if err != nil {
			return fmt.Errorf("Unsupported default ingress class: '%s'. You can set the ingress class with 'LEGO_DEFAULT_INGRESS_CLASS'", defaultIngressClass)
		}
	}
	kl.ingressNameNginx = os.Getenv("LEGO_INGRESS_NAME_NGINX")
	if len(kl.ingressNameNginx) == 0 {
		kl.ingressNameNginx = os.Getenv("LEGO_INGRESS_NAME")
		if len(kl.ingressNameNginx) == 0 {
			kl.ingressNameNginx = "kube-lego-nginx"
		}
	}

	checkIntervalString := os.Getenv("LEGO_CHECK_INTERVAL")
	if len(checkIntervalString) == 0 {
		kl.checkInterval = 8 * time.Hour
	} else {
		d, err := time.ParseDuration(checkIntervalString)
		if err != nil {
			return err
		}
		if d < 5*time.Minute {
			return fmt.Errorf("Minimum check interval is 5 minutes: %s", d)
		}
		kl.checkInterval = d
	}

	kl.kubeAPIURL = os.Getenv("LEGO_KUBE_API_URL")
	if len(kl.kubeAPIURL) == 0 {
		kl.kubeAPIURL = "http://127.0.0.1:8080"
	}

	minimumValidity := os.Getenv("LEGO_MINIMUM_VALIDITY")
	if len(minimumValidity) == 0 {
		kl.minimumValidity = time.Hour * 24 * 30
	} else {
		d, err := time.ParseDuration(minimumValidity)
		if err != nil {
			return err
		}
		if d < 24*time.Hour {
			return fmt.Errorf("Smallest allowed minimum validity is 24 hours: %s", d)
		}
		kl.minimumValidity = d
	}

	httpPortStr := os.Getenv("LEGO_PORT")
	if len(httpPortStr) == 0 {
		kl.httpPort = intstr.FromInt(8080)
	} else {
		i, err := strconv.Atoi(httpPortStr)
		if err != nil {
			return err
		}
		if i <= 0 || i >= 65535 {
			return fmt.Errorf("Wrong port: %d", i)
		}
		kl.httpPort = intstr.FromInt(i)
	}

	annotationEnabled := os.Getenv("LEGO_KUBE_ANNOTATION")
	if len(annotationEnabled) != 0 {
		kubelego.AnnotationEnabled = annotationEnabled
	}

	svcSelector := os.Getenv("LEGO_SERVICE_SELECTOR")
	if len(svcSelector) != 0 {
		kubelego.LegoServiceSelector = svcSelector
	}

	watchNamespace := os.Getenv("LEGO_WATCH_NAMESPACE")
	if len(watchNamespace) == 0 {
		kl.watchNamespace = k8sApi.NamespaceAll
	} else {
		kl.watchNamespace = watchNamespace
	}
	return nil
}
