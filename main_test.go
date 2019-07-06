package main

import (
	"encoding/json"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/awstesting/unit"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/aws/aws-sdk-go/service/sts/stsiface"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

const instanceIdentityDocument = `{
  "availabilityZone" : "us-east-1d",
  "privateIp" : "10.158.112.84",
  "version" : "2010-08-31",
  "region" : "us-east-1",
  "instanceId" : "i-1234567890abcdef0",
  "billingProducts" : null,
  "instanceType" : "t1.micro",
  "accountId" : "123456789012",
  "pendingTime" : "2015-11-19T16:32:11Z",
  "imageId" : "ami-5fb8c835",
  "kernelId" : "aki-919dcaf8",
  "ramdiskId" : null,
  "architecture" : "x86_64"
}`

type IIDocument struct {
	AvailabilityZone string      `json:"availabilityZone"`
	PrivateIP        string      `json:"privateIp"`
	Version          string      `json:"version"`
	Region           string      `json:"region"`
	InstanceID       string      `json:"instanceId"`
	BillingProducts  interface{} `json:"billingProducts"`
	InstanceType     string      `json:"instanceType"`
	AccountID        string      `json:"accountId"`
	PendingTime      time.Time   `json:"pendingTime"`
	ImageID          string      `json:"imageId"`
	KernelID         string      `json:"kernelId"`
	RamdiskID        interface{} `json:"ramdiskId"`
	Architecture     string      `json:"architecture"`
}

var iIDocument IIDocument

func initTestServer(path string, resp string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.RequestURI != path {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Write([]byte(resp))
	}))
}

func TestEC2Metadata(t *testing.T) {
	server := initTestServer(
		"/latest/dynamic/instance-identity/document",
		instanceIdentityDocument,
	)
	defer server.Close()

	region, instanceID, accountID := ec2Metadata(unit.Session, &aws.Config{Endpoint: aws.String(server.URL + "/latest")})

	json.Unmarshal([]byte(instanceIdentityDocument), &iIDocument)

	if region != iIDocument.Region {
		t.Fatalf("Something went wrong expecting region: %v and I've got: %v", region, iIDocument.Region)
	}
	if instanceID != iIDocument.InstanceID {
		t.Fatalf("Something went wrong expecting instanceID: %v and I've got: %v", instanceID, iIDocument.InstanceID)
	}
	if accountID != iIDocument.AccountID {
		t.Fatalf("Something went wrong expecting region: %v and I've got: %v", region, iIDocument.AccountID)
	}

}

type mockedGetTagValue struct {
	ec2iface.EC2API
	Resp ec2.DescribeInstancesOutput
}

func (m mockedGetTagValue) DescribeInstances(in *ec2.DescribeInstancesInput) (*ec2.DescribeInstancesOutput, error) {
	return &m.Resp, nil
}

func TestGetTagValue(t *testing.T) {
	cases := []struct {
		Resp     ec2.DescribeInstancesOutput
		Expected ec2.Tag
	}{
		{
			Resp: ec2.DescribeInstancesOutput{
				Reservations: []*ec2.Reservation{
					{
						Instances: []*ec2.Instance{
							{
								Tags: []*ec2.Tag{
									{
										Key:   aws.String("auth-account-arn"),
										Value: aws.String("arn:aws:iam::434342352745:role/RoleCrossAccountSSH")},
								},
							},
						},
					},
				},
			},
			Expected: ec2.Tag{
				Value: aws.String("arn:aws:iam::434342352745:role/RoleCrossAccountSSH"),
			},
		},
	}

	for _, c := range cases {
		tv := Tag{
			Client:     mockedGetTagValue{Resp: c.Resp},
			TagName:    "auth-account-arn",
			InstanceId: "InstanceId_%d",
			Region:     "Region",
		}

		tagValue := tv.getTagValue()

		if tagValue != *c.Expected.Value {
			t.Fatalf("Something went wrong expecting TagValue: %v and I've got: %v", *c.Expected.Value, tagValue)
		}
	}
}

type mockedAccessKeyIdSecretAccessKeySessionToken struct {
	stsiface.STSAPI
	Resp sts.AssumeRoleOutput
}

func (m mockedAccessKeyIdSecretAccessKeySessionToken) AssumeRole(in *sts.AssumeRoleInput) (*sts.AssumeRoleOutput, error) {
	return &m.Resp, nil
}

func TestGetAccessKeyIdSecretAccessKeySessionToken(t *testing.T) {
	cases := []struct {
		Resp     sts.AssumeRoleOutput
		Expected sts.Credentials
	}{
		{
			Resp: sts.AssumeRoleOutput{
				Credentials: &sts.Credentials{
					AccessKeyId:     aws.String("accesskeyid"),
					SecretAccessKey: aws.String("secrectaccesskey"),
					SessionToken:    aws.String("sessiontoken"),
				},
			},
			Expected: sts.Credentials{
				AccessKeyId:     aws.String("accesskeyid"),
				SecretAccessKey: aws.String("secrectaccesskey"),
				SessionToken:    aws.String("sessiontoken"),
			},
		},
	}

	for _, c := range cases {
		at := AccessKeyIdSecretAccessKeySessionToken{
			Client:         mockedAccessKeyIdSecretAccessKeySessionToken{Resp: c.Resp},
			AuthAccountArn: "auth-account-arn",
			UserId:         "UserId",
			AccountID:      "Region",
		}

		accessKeyId, secretAccessKey, sessionToken := at.getAccessKeyIdSecretAccessKeySessionToken()

		if accessKeyId != *c.Expected.AccessKeyId {
			t.Fatalf("Something went wrong expecting AccesskeyId: %v and I've got: %v", *c.Expected.AccessKeyId, accessKeyId)
		}
		if secretAccessKey != *c.Expected.SecretAccessKey {
			t.Fatalf("Something went wrong expecting SecrectAccessKey: %v and I've got: %v", *c.Expected.SecretAccessKey, secretAccessKey)
		}
		if sessionToken != *c.Expected.SessionToken {
			t.Fatalf("Something went wrong expecting SessionToken: %v and I've got: %v", *c.Expected.SessionToken, sessionToken)
		}
	}
}

type mockedGetPubKey struct {
	iamiface.IAMAPI
	Resp    iam.GetSSHPublicKeyOutput
	Request request.Request
}

func (m mockedGetPubKey) GetSSHPublicKeyRequest(in *iam.GetSSHPublicKeyInput) (*request.Request, *iam.GetSSHPublicKeyOutput) {
	return &m.Request, &m.Resp
}

func TestGetPubKey(t *testing.T) {
	cases := []struct {
		Request  request.Request
		Resp     iam.GetSSHPublicKeyOutput
		Expected iam.SSHPublicKey
	}{
		{
			Resp: iam.GetSSHPublicKeyOutput{
				SSHPublicKey: &iam.SSHPublicKey{
					SSHPublicKeyBody: aws.String("SSHPublicKeyBody"),
				},
			},
			Expected: iam.SSHPublicKey{
				SSHPublicKeyBody: aws.String("SSHPublicKeyBody"),
			},
		},
	}

	for _, c := range cases {
		pk := PubKey{
			Client: mockedGetPubKey{
				Request: c.Request,
				Resp:    c.Resp,
			},
			Region:          "eu-west-2",
			UserID:          "user.name",
			SecretAccessKey: "secrectaccesskey",
			AccessKeyId:     "accesskeyid",
			SessionToken:    "sessiontoken",
		}

		pubKey := pk.getPubKey("user.name")

		if pubKey != *c.Expected.SSHPublicKeyBody {
			t.Fatalf("Something went wrong expecting pubKey: %v and I've got: %v", *c.Expected.SSHPublicKeyBody, pubKey)
		}
	}
}

type mockedListPubKey struct {
	iamiface.IAMAPI
	Resp    iam.ListSSHPublicKeysOutput
	Request request.Request
}

func (m mockedListPubKey) ListSSHPublicKeysRequest(in *iam.ListSSHPublicKeysInput) (*request.Request, *iam.ListSSHPublicKeysOutput) {
	return &m.Request, &m.Resp
}

func TestListPublicKeys(t *testing.T) {
	cases := []struct {
		Request  request.Request
		Resp     iam.ListSSHPublicKeysOutput
		Expected []*iam.SSHPublicKey
	}{
		{
			Resp: iam.ListSSHPublicKeysOutput{
				SSHPublicKeys: []*iam.SSHPublicKeyMetadata{
					{
						Status:         aws.String("Active"),
						SSHPublicKeyId: aws.String("user1.name"),
					},
					{
						Status:         aws.String("Inactive"),
						SSHPublicKeyId: aws.String("user2.name"),
					},
				},
			},
			Expected: []*iam.SSHPublicKey{
				{
					Status:         aws.String("Active"),
					SSHPublicKeyId: aws.String("user1.name"),
				},
				{
					Status:         aws.String("Inactive"),
					SSHPublicKeyId: aws.String("user2.name"),
				},
			},
		},
	}

	for _, c := range cases {
		pk := PubKey{
			Client: mockedListPubKey{
				Request: c.Request,
				Resp:    c.Resp,
			},
			Region:          "eu-west-2",
			UserID:          "user.name",
			SecretAccessKey: "secrectaccesskey",
			AccessKeyId:     "accesskeyid",
			SessionToken:    "sessiontoken",
		}

		for i, PubKey := range pk.listPublicKeys() {
			if *PubKey.Status != *c.Expected[i].Status {
				t.Fatalf("Something went wrong expecting pubKey Staus: %v and I've got: %v", *PubKey.Status, *c.Expected[i].Status)
			}
		}
	}
}

func TestGetActivePubKeyWithActive(t *testing.T) {
	cases := []struct {
		Request  request.Request
		Resp     iam.ListSSHPublicKeysOutput
		Expected []*iam.SSHPublicKey
	}{
		{
			Resp: iam.ListSSHPublicKeysOutput{
				SSHPublicKeys: []*iam.SSHPublicKeyMetadata{
					{
						Status:         aws.String("Active"),
						SSHPublicKeyId: aws.String("user1.name"),
					},
				},
			},
			Expected: []*iam.SSHPublicKey{
				{
					SSHPublicKeyId: aws.String("user1.name"),
				},
			},
		},
	}

	for _, c := range cases {
		pk := PubKey{
			Client: mockedListPubKey{
				Request: c.Request,
				Resp:    c.Resp,
			},
			Region:          "eu-west-2",
			UserID:          "user.name",
			SecretAccessKey: "secrectaccesskey",
			AccessKeyId:     "accesskeyid",
			SessionToken:    "sessiontoken",
		}

		pubKey := pk.listPublicKeys()
		pKey := pk.getActivePubKey(pubKey)

		if pKey != *c.Expected[0].SSHPublicKeyId {
			t.Fatalf("Something went wrong expecting pubKey Staus: %v and I've got: %v", pKey, *c.Expected[0].SSHPublicKeyId)
		}
	}
}

func TestGetActivePubKeyWithInctive(t *testing.T) {
	cases := []struct {
		Request  request.Request
		Resp     iam.ListSSHPublicKeysOutput
		Expected []*iam.SSHPublicKey
	}{
		{
			Resp: iam.ListSSHPublicKeysOutput{
				SSHPublicKeys: []*iam.SSHPublicKeyMetadata{
					{
						Status:         aws.String("Inactive"),
						SSHPublicKeyId: aws.String("user2.name"),
					},
				},
			},
			Expected: []*iam.SSHPublicKey{
				{
					SSHPublicKeyId: aws.String(""),
				},
			},
		},
	}

	for _, c := range cases {
		pk := PubKey{
			Client: mockedListPubKey{
				Request: c.Request,
				Resp:    c.Resp,
			},
			Region:          "eu-west-2",
			UserID:          "user.name",
			SecretAccessKey: "secrectaccesskey",
			AccessKeyId:     "accesskeyid",
			SessionToken:    "sessiontoken",
		}

		pubKey := pk.listPublicKeys()
		pKey := pk.getActivePubKey(pubKey)

		if pKey != *c.Expected[0].SSHPublicKeyId {
			t.Fatalf("Something went wrong expecting pubKey Staus: %v and I've got: %v", pKey, *c.Expected[0].SSHPublicKeyId)
		}
	}
}
