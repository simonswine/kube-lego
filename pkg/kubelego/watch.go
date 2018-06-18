package kubelego

import (
	"reflect"
	"time"

	"github.com/jetstack/kube-lego/pkg/ingress"
	klconst "github.com/jetstack/kube-lego/pkg/kubelego_const"

	k8sMeta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	watch "k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	k8sExtensions "k8s.io/client-go/pkg/apis/extensions/v1beta1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

func ingressListFunc(c *kubernetes.Clientset, ns string) func(k8sMeta.ListOptions) (runtime.Object, error) {
	return func(opts k8sMeta.ListOptions) (runtime.Object, error) {
		return c.Extensions().Ingresses(ns).List(opts)
	}
}

func ingressWatchFunc(c *kubernetes.Clientset, ns string) func(options k8sMeta.ListOptions) (watch.Interface, error) {
	return func(options k8sMeta.ListOptions) (watch.Interface, error) {
		return c.Extensions().Ingresses(ns).Watch(options)
	}
}

// requestReconfigure will trigger a resync of *all* ingress resources.
func (kl *KubeLego) requestReconfigure() error {
	allIng, err := ingress.All(kl)
	if err != nil {
		return err
	}
	for _, ing := range allIng {
		key, err := cache.MetaNamespaceKeyFunc(ing.Object())
		if err != nil {
			return err
		}
		kl.workQueue.AddRateLimited(key)
	}
	return nil
}

func (kl *KubeLego) WatchReconfigure() {

	kl.workQueue = workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(time.Minute*10, time.Hour*24), "kube-lego")

	// handle worker shutdown
	go func() {
		<-kl.stopCh
		kl.workQueue.ShutDown()
	}()

	go func() {
		kl.waitGroup.Add(1)
		defer kl.waitGroup.Done()
		for {
			item, quit := kl.workQueue.Get()
			if quit {
				return
			}
			func(item interface{}) {
				defer kl.workQueue.Done(item)
				key, ok := item.(string)
				if !ok {
					kl.Log().Errorf("worker: invalid item in workqueue: %v", item)
					kl.workQueue.Forget(item)
					return
				}
				namespace, name, err := cache.SplitMetaNamespaceKey(key)
				if err != nil {
					kl.Log().Errorf("worker: invalid string in workqueue %q: %v", item, err)
					kl.workQueue.Forget(item)
					return
				}
				kl.Log().Debugf("worker: begin processing %v", key)
				// attempt to get an internal ingress type.
				ing := ingress.New(kl, namespace, name)
				// if it doesn't exist for some reason, exit here and forget the
				// item from the workqueue.
				if ing.Exists == false {
					kl.Log().Errorf("worker: ingress for key %q no longer exists. Skipping...", key)
					kl.workQueue.Forget(item)
					return
				}
				// attempt to process the ingress
				err = kl.reconfigure(ing)
				if err != nil {
					kl.Log().Errorf("worker: error processing item, requeuing after rate limit: %v", err)
					// we requeue the item and skip calling Forget here to ensure
					// a rate limit is applied when adding the item after a failure
					kl.workQueue.AddRateLimited(key)
					return
				}
				kl.Log().Debugf("worker: done processing %v", key)
				// as this validation was a success, we should forget the item from
				// the workqueue.
				kl.workQueue.Forget(item)
			}(item)
		}
	}()
}

func (kl *KubeLego) WatchEvents() {

	kl.Log().Debugf("start watching ingress objects")

	resyncPeriod := 10 * time.Minute

	ingEventHandler := cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			addIng := obj.(*k8sExtensions.Ingress)
			if ingress.IgnoreIngress(addIng) != nil {
				return
			}
			kl.Log().Debugf("CREATE ingress/%s/%s", addIng.Namespace, addIng.Name)
			if key, err := cache.MetaNamespaceKeyFunc(addIng); err != nil {
				kl.Log().Errorf("worker: failed to key ingress: %v", err)
				return
			} else {
				kl.Log().Infof("Queued item %q to be processed immediately", key)
				// immediately queue creation events.
				// if we called AddRateLimited here, we would initially wait 10m
				// before processing anything at all.
				kl.workQueue.Add(key)
			}
		},
		DeleteFunc: func(obj interface{}) {
			delIng := obj.(*k8sExtensions.Ingress)
			if ingress.IgnoreIngress(delIng) != nil {
				return
			}
			kl.Log().Debugf("DELETE ingress/%s/%s", delIng.Namespace, delIng.Name)
			if key, err := cache.MetaNamespaceKeyFunc(delIng); err != nil {
				kl.Log().Errorf("worker: failed to key ingress: %v", err)
				return
			} else {
				kl.Log().Infof("Detected deleted ingress %q - skipping", key)
				// skip processing deleted items, as there is no reason to due to
				// the way kube-lego serialises authorization attempts
				// kl.workQueue.AddRateLimited(key)
				kl.workQueue.Forget(key)
			}
		},
		UpdateFunc: func(old, cur interface{}) {
			oldIng := old.(*k8sExtensions.Ingress)
			upIng := cur.(*k8sExtensions.Ingress)

			shouldForceProcess := anyDifferent(oldIng.Annotations, upIng.Annotations,
				klconst.AnnotationIngressClass,
				klconst.AnnotationIngressProvider,
				klconst.AnnotationKubeLegoManaged,
				klconst.AnnotationSslRedirect,
				klconst.AnnotationWhitelistSourceRange)

			// we requeue ingresses only when their spec has changed, as the indicates
			// a user has updated the specification of their ingress and as such we should
			// re-trigger a validation if required.
			if !reflect.DeepEqual(oldIng.Spec, upIng.Spec) || shouldForceProcess {
				upIng := cur.(*k8sExtensions.Ingress)
				if ingress.IgnoreIngress(upIng) != nil {
					return
				}
				kl.Log().Debugf("UPDATE ingress/%s/%s", upIng.Namespace, upIng.Name)
				if key, err := cache.MetaNamespaceKeyFunc(upIng); err != nil {
					kl.Log().Errorf("worker: failed to key ingress: %v", err)
					return
				} else {
					kl.Log().Infof("Detected spec change - queued ingress %q to be processed", key)
					// immediately queue the item, as its spec has changed so it may now
					// be valid
					kl.workQueue.Add(key)
				}
			}
		},
	}

	_, controller := cache.NewInformer(
		&cache.ListWatch{
			ListFunc:  ingressListFunc(kl.kubeClient, kl.legoWatchNamespace),
			WatchFunc: ingressWatchFunc(kl.kubeClient, kl.legoWatchNamespace),
		},
		&k8sExtensions.Ingress{},
		resyncPeriod,
		ingEventHandler,
	)

	go controller.Run(kl.stopCh)
}

// anyDifferent returns true if any of the keys passed are different in the given
// map.
func anyDifferent(left, right map[string]string, keys ...string) bool {
	// if either left or right are nil, and the other isn't, then
	// return true to kick off re-processing
	if left == nil && right == nil ||
		left == nil && right != nil ||
		left != nil && right == nil {
		return true
	}
	for _, k := range keys {
		if left[k] != right[k] {
			return true
		}
	}
	return false
}
