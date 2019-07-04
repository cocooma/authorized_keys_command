package main

import (
	"fmt"
	//"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/aws/aws-sdk-go/service/sts/stsiface"
	"testing"
)

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
										Value: aws.String("arn:aws:iam::638924580364:role/RoleCrossAccountSSH")},
								},
							},
						},
					},
				},
			},
			Expected: ec2.Tag{
				Value: aws.String("arn:aws:iam::638924580364:role/RoleCrossAccountSSH"),
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

		tagValue, err := tv.getTagValue()

		if err != nil {
			t.Fatalf("%d, unexpected error", err)
		}

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
				AssumedRoleUser: &sts.AssumedRoleUser{
					AssumedRoleId: aws.String("asda"),
					Arn:           aws.String("dsa"),
				},
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
		fmt.Println(c.Resp)
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
