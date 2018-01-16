# Roadmap

An overview of what the direction of kube-lego should like over the next months

## Stabilizing 0.1.x

My main concern before adding new features would be to stablize what is currently out there.

* Automated testing of existing features (esp. the variations out there: multi-
vs. single-namespace and gce- vs. nginx-ingress)

* Role Based Access control

* Rate limiting of authorizations

* Handle continuously failing domains, more gracefully (failure bucket, blacklist)

## Features 0.2 and beyond

These features are in no particular order right now. They are possibly breaking
changes and should only be high-level summaries. For the details we need to
have an issues.

### Third party object storage backend

### Support for DNS validations

### Provide kube-lego status page on HTTP endpoint

### Provide prometheus metrics on HTTP endpoint
