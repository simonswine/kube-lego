package ingress

import (
	"testing"

	"github.com/stretchr/testify/assert"
	k8sExtensions "k8s.io/client-go/pkg/apis/extensions/v1beta1"
)

func TestTls_Validate(t *testing.T) {
	tt := []struct {
		name       string
		secretname string
		hosts      []string
		expectErr  bool
	}{
		{
			name:       "no hosts",
			secretname: "my-secret",
			hosts:      nil,
			expectErr:  true,
		},
		{
			name:       "no secret",
			secretname: "",
			hosts:      []string{"das.de.de", "k8s.io"},
			expectErr:  true,
		},
		{
			name:       "correct tls",
			secretname: "my-secret",
			hosts:      []string{"das.de.de", "k8s.io"},
			expectErr:  false,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			ing := &Ingress{}
			tls := NewTls(
				&k8sExtensions.IngressTLS{
					Hosts:      tc.hosts,
					SecretName: tc.secretname,
				},
				ing,
			)

			err := tls.Validate()
			if tc.expectErr {
				assert.NotNil(t, err, "validate fails for ", tc.name)
			} else {
				assert.Nil(t, err, "validate fails for ", tc.name)
			}
		})
	}

}
