# kube-lego example

This document demonstrates how to deploy kube-lego to the
[HAProxy Ingress](https://github.com/jcmoraisjr/haproxy-ingress) controller.

## Deploy the Ingress controller

Follow the [deployment instructions](https://github.com/kubernetes/ingress/tree/master/examples/deployment/haproxy)
including the deployment of the optional web app for testing.

## Deploy kube-lego

The following instruction will create the kube-lego deployment on it's own namespace.
Be aware that kube-lego creates it's related service on its own.

* Change `LEGO_EMAIL` to your email address
* Uncomment `LEGO_URL` to use the production API

```console
kubectl create ns kube-lego
kubectl create -f deployment.yaml
```

## Enable kube-lego in the testing application

This will add a TLS secret name and tls-acme annotation to the ingress resource created
in the deployment instruction.

* Change both `echo.example.com` to the public domain of your Ingress controller

```console
kubectl replace -f app-ingress.yaml
```

The `app-tls` secret and the https url should be updated. Check the log output of
HAProxy Ingress and kube-lego pods if this doesn't happen.
