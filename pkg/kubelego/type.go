package kubelego

import (
	"net"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/jetstack/kube-lego/pkg/ingress"
	"github.com/jetstack/kube-lego/pkg/kubelego_const"

	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/workqueue"
)

type KubeLego struct {
	url                      string
	email                    string
	secretName               string
	ingressNameNginx         string
	namespace                string
	podIP                    net.IP
	serviceNameNginx         string
	serviceNameGCE           string
	supportedIngressClass    []string
	supportedIngressProvider []string
	httpPort                 intstr.IntOrString
	checkInterval            time.Duration
	minimumValidity          time.Duration
	defaultIngressClass      string
	defaultIngressProvider   string
	kubeAPIURL               string
	watchNamespace           string
	kubeClient               *kubernetes.Clientset
	ingressSlice             []*ingress.Ingress
	ingressProvider          map[string]kubelego.IngressProvider
	log                      *log.Entry
	version                  string
	acmeClient               kubelego.Acme

	// stop channel for services
	stopCh chan struct{}

	// wait group
	waitGroup sync.WaitGroup

	// work queue
	workQueue *workqueue.Type
}
