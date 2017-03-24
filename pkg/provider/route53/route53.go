package route53

import (
	"fmt"
	"github.com/Sirupsen/logrus"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/route53"
	"github.com/jetstack/kube-lego/pkg/kubelego_const"
	"time"
)

var _ kubelego.DnsProvider = &Route53{}

type Route53 struct {
	kubelego   kubelego.KubeLego
	hosts      map[string]bool
	awsConfig  *aws.Config
	session    *session.Session
	recordName string
}

func New(kl kubelego.KubeLego) *Route53 {

	return &Route53{awsConfig: &aws.Config{
		Credentials: credentials.NewChainCredentials(
			[]credentials.Provider{
				&credentials.EnvProvider{},
				&credentials.SharedCredentialsProvider{},
			}),
	}}

}

func (r *Route53) Log() (log *logrus.Entry) {
	return r.kubelego.Log().WithField("context", "provider").WithField("provider", "route53")

}

func (r *Route53) Finalize() error {
	//TODO implement cleanup
	r.Log().Debug("finalize")
	return nil

}

func (r *Route53) CreateRecordset(domain string, challengeValue string) error {

	sess, err := session.NewSession(r.awsConfig)

	if err != nil {
		return err
	}

	r53 := route53.New(sess)

	hostedZoneId, err := r.getHostedZoneID(domain)

	if err != nil {
		return err
	}

	challengeValue = fmt.Sprintf(`"%v"`, challengeValue)
	r.recordName = fmt.Sprintf("%v.%v.", "_acme-challenge", domain)

	// prepare upsert request
	input := &route53.ChangeResourceRecordSetsInput{
		ChangeBatch: &route53.ChangeBatch{
			Changes: []*route53.Change{
				{
					Action: aws.String(route53.ChangeActionUpsert),
					ResourceRecordSet: &route53.ResourceRecordSet{
						Name: aws.String(r.recordName),
						Type: aws.String(route53.RRTypeTxt),
						ResourceRecords: []*route53.ResourceRecord{
							{
								Value: aws.String(challengeValue),
							},
						},
						TTL: aws.Int64(300),
					},
				},
			},
		},
		HostedZoneId: aws.String(hostedZoneId),
	}

	if _, err := r53.ChangeResourceRecordSets(input); err != nil {
		return err
	}

	return nil
}

func (r *Route53) getHostedZoneID(domain string) (string, error) {
	return "FAKE_ZONE_ID", nil
}

func (r *Route53) TestRecordset() error {

	//TODO implement
	timeout := time.After(40 * time.Second)
	tick := time.Tick(15000 * time.Millisecond)

	for {
		select {
		case <-timeout:
			return fmt.Errorf("timed out TestRecordset %s", r.recordName)

		case <-tick:

			return nil
		}
	}
}
