package main

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/defaults"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/aws/aws-sdk-go/service/sts/stsiface"
	"os"
)

func ec2Metadata() (region, instanceID, accountID string) {
	client := ec2metadata.New(session.Must(session.NewSession()))
	ec2InstanceIdentifyDocument, _ := client.GetInstanceIdentityDocument()
	region = ec2InstanceIdentifyDocument.Region
	instanceID = ec2InstanceIdentifyDocument.InstanceID
	accountID = ec2InstanceIdentifyDocument.AccountID
	return
}

type Tag struct {
	Client     ec2iface.EC2API
	TagName    string
	InstanceId string
	Region     string
}

func (t *Tag) getTagValue() (value string, err error) {
	params := &ec2.DescribeInstancesInput{
		InstanceIds: []*string{
			aws.String(t.InstanceId),
		},
	}
	resp, err := t.Client.DescribeInstances(params)
	if err != nil {
		fmt.Printf("%s", err)
		return "", err
	}
	if len(resp.Reservations) == 0 {
		return "", err
	}

	for idx := range resp.Reservations {
		for _, inst := range resp.Reservations[idx].Instances {
			for _, tag := range inst.Tags {
				if (t.TagName != "") && (*tag.Key == t.TagName) {
					return *tag.Value, nil
				}
			}
		}
	}
	return
}

type AccessKeyIdSecretAccessKeySessionToken struct {
	Client         stsiface.STSAPI
	AuthAccountArn string
	UserId         string
	AccountID      string
}

func (a *AccessKeyIdSecretAccessKeySessionToken) getAccessKeyIdSecretAccessKeySessionToken() (accessKeyId, secretAccessKey, sessionToken string) {
	params := &sts.AssumeRoleInput{
		DurationSeconds: aws.Int64(3600),
		RoleArn:         aws.String(a.AuthAccountArn),
		RoleSessionName: aws.String("auth_keys_cmd_" + a.UserId + "_" + a.AccountID),
	}
	result, _ := a.Client.AssumeRole(params)
	accessKeyId = *result.Credentials.AccessKeyId
	secretAccessKey = *result.Credentials.SecretAccessKey
	sessionToken = *result.Credentials.SessionToken
	return
}

func getPubKey(region, userID, sSHPublicKeyId, secretAccessKey, accessKeyId, sessionToken string) {
	svc := iam.New(session.New(&aws.Config{
		Region: aws.String(region),
		Credentials: credentials.NewChainCredentials(
			[]credentials.Provider{
				&credentials.StaticProvider{
					Value: credentials.Value{
						AccessKeyID:     accessKeyId,
						SecretAccessKey: secretAccessKey,
						SessionToken:    sessionToken,
					},
				},
				&credentials.EnvProvider{},
				&credentials.SharedCredentialsProvider{},
				defaults.RemoteCredProvider(*(defaults.Config()), defaults.Handlers()),
			}),
	}))
	params := &iam.GetSSHPublicKeyInput{
		Encoding:       aws.String("SSH"),
		SSHPublicKeyId: aws.String(sSHPublicKeyId),
		UserName:       aws.String(userID),
	}

	req, resp := svc.GetSSHPublicKeyRequest(params)
	req.Send()
	fmt.Println(*resp.SSHPublicKey.SSHPublicKeyBody)
}

func listPublicKeys(region, accessKeyId, secretAccessKey, sessionToken, userid string) {
	svc := iam.New(session.New(&aws.Config{
		Region: aws.String(region),
		Credentials: credentials.NewChainCredentials(
			[]credentials.Provider{
				&credentials.StaticProvider{
					Value: credentials.Value{
						AccessKeyID:     accessKeyId,
						SecretAccessKey: secretAccessKey,
						SessionToken:    sessionToken,
					},
				},
				&credentials.EnvProvider{},
				&credentials.SharedCredentialsProvider{},
				defaults.RemoteCredProvider(*(defaults.Config()), defaults.Handlers()),
			}),
	}))
	param := &iam.ListSSHPublicKeysInput{
		UserName: aws.String(userid),
	}
	req, resp := svc.ListSSHPublicKeysRequest(param)
	err := req.Send()
	if err == nil { // resp is now filled
		for _, SSHPublicKey := range resp.SSHPublicKeys {
			if *SSHPublicKey.Status == "Active" {
				sSHPublicKeyId := *SSHPublicKey.SSHPublicKeyId
				getPubKey(region, userid, sSHPublicKeyId, secretAccessKey, accessKeyId, sessionToken)
			}
		}
	}
}

func main() {

	userid := ""
	if len(os.Args) > 1 {
		userid = os.Args[1]
	} else {
		os.Exit(0)
	}

	region, instanceID, accountID := ec2Metadata()

	sess := session.Must(session.NewSession((&aws.Config{Region: aws.String(region)})))

	t := Tag{
		Client:     ec2.New(sess),
		TagName:    "auth-account-arn",
		InstanceId: instanceID,
		Region:     region,
	}

	authAccountArn, _ := t.getTagValue()

	a := AccessKeyIdSecretAccessKeySessionToken{
		Client:         sts.New(sess),
		AuthAccountArn: authAccountArn,
		UserId:         userid,
		AccountID:      accountID,
	}

	accessKeyId, secretAccessKey, sessionToken := a.getAccessKeyIdSecretAccessKeySessionToken()

	listPublicKeys(region, accessKeyId, secretAccessKey, sessionToken, userid)

}
