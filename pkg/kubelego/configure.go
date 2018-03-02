package kubelego

import (
	"github.com/jetstack/kube-lego/pkg/ingress"
	"github.com/jetstack/kube-lego/pkg/kubelego_const"

	"fmt"
	"strings"
)

func (kl *KubeLego) TlsIgnoreDuplicatedSecrets(tlsSlice []kubelego.Tls) []kubelego.Tls {

	tlsBySecret := make(map[string]kubelego.Tls)

	for _, elm := range tlsSlice {
		key := fmt.Sprintf(
			"%s/%s",
			elm.SecretMetadata().Namespace,
			elm.SecretMetadata().Name,
		)

		if t, ok := tlsBySecret[key]; ok {
			for _, h := range elm.Hosts() {
				t.AddHost(h)
			}
		} else {
			tlsBySecret[key] = elm
		}

	}

	output := make([]kubelego.Tls, 0, len(tlsBySecret))
	for _, v := range tlsBySecret {
		output = append(output, v)
	}

	return output
}

func (kl *KubeLego) processProvider(ings []kubelego.Ingress) (err error) {

	for providerName, provider := range kl.legoIngressProvider {
		err := provider.Reset()
		if err != nil {
			provider.Log().Error(err)
			continue
		}

		for _, ing := range ings {
			if providerName == ing.IngressProvider() {
				err = provider.Process(ing)
				if err != nil {
					provider.Log().Error(err)
				}
			}
		}

		err = provider.Finalize()
		if err != nil {
			provider.Log().Error(err)
		}
	}
	return nil
}

func (kl *KubeLego) reconfigure(ingressesAll []kubelego.Ingress) error {
	tlsSlice := []kubelego.Tls{}
	ingresses := []kubelego.Ingress{}

	// filter ingresses, collect tls names
	for _, ing := range ingressesAll {
		if ing.Ignore() {
			continue
		}
		tlsSlice = append(tlsSlice, ing.Tls()...)
		ingresses = append(ingresses, ing)
	}

	// setup providers
	kl.processProvider(ingresses)

	// normify tls config
	tlsSlice = kl.TlsIgnoreDuplicatedSecrets(tlsSlice)

	// process certificate validity
	kl.Log().Info("process certificate requests for ingresses")
	errs := kl.TlsProcessHosts(tlsSlice)
	if len(errs) > 0 {
		errsStr := []string{}
		for _, err := range errs {
			errsStr = append(errsStr, fmt.Sprintf("%s", err))
		}
		kl.Log().Error("Error while processing certificate requests: ", strings.Join(errsStr, ", "))

		// request a rerun of reconfigure
		kl.workQueue.Add(true)
	}

	return nil
}

func (kl *KubeLego) Reconfigure() error {
	ingressesAll, err := ingress.All(kl)
	if err != nil {
		return err
	}

	return kl.reconfigure(ingressesAll)
}

func (kl *KubeLego) TlsProcessHosts(tlsSlice []kubelego.Tls) []error {
	errs := []error{}
	for _, tlsElem := range tlsSlice {
		err := tlsElem.Process()
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}
