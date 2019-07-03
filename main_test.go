package main

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
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
		Resp ec2.DescribeInstancesOutput
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
		},
	}

	for _, c := range cases {
		tv := Tag{
			Client:     mockedGetTagValue{Resp: c.Resp},
			TagName:    "auth-account-arn",
			InstanceId: "InstanceId_%d",
			Region:     "Region",
		}
		expectedTagValue := "arn:aws:iam::638924580364:role/RoleCrossAccountSSH"

		tagValue, err := tv.getTagValue()

		if err != nil {
			t.Fatalf("%d, unexpected error", err)
		}

		if tagValue != expectedTagValue {
			t.Fatalf("Something went wrong expecting TagValue: %v and I've got: %v", expectedTagValue, tagValue)
		}
	}
}
