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
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/aws/aws-sdk-go/service/sts/stsiface"
	"os"
)

var version string

func ec2Metadata(sess *session.Session, awsCfg *aws.Config) (region, instanceID, accountID string) {
	client := ec2metadata.New(sess, awsCfg)
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

//Retrieves the ec2 tag-value for the given ec2 tag-name
func (t *Tag) getTagValue() (value string) {
	params := &ec2.DescribeInstancesInput{
		InstanceIds: []*string{
			aws.String(t.InstanceId),
		},
	}
	resp, err := t.Client.DescribeInstances(params)
	if err != nil {
		fmt.Printf("%s", err)
		os.Exit(1)
	}
	if len(resp.Reservations) == 0 {
		fmt.Printf("%s", err)
		os.Exit(1)
	}

	for idx := range resp.Reservations {
		for _, inst := range resp.Reservations[idx].Instances {
			for _, tag := range inst.Tags {
				if (t.TagName != "") && (*tag.Key == t.TagName) {
					return *tag.Value
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

//Assumes the AWS role and retrieves the temporary credentials
func (a *AccessKeyIdSecretAccessKeySessionToken) getAccessKeyIdSecretAccessKeySessionToken() (accessKeyId, secretAccessKey, sessionToken string) {
	params := &sts.AssumeRoleInput{
		DurationSeconds: aws.Int64(3600),
		RoleArn:         aws.String(a.AuthAccountArn),
		RoleSessionName: aws.String("auth_keys_cmd_" + a.UserId + "_" + a.AccountID),
	}
	result, err := a.Client.AssumeRole(params)
	if err != nil {
		fmt.Printf("%s", err)
		os.Exit(1)
	}
	accessKeyId = *result.Credentials.AccessKeyId
	secretAccessKey = *result.Credentials.SecretAccessKey
	sessionToken = *result.Credentials.SessionToken
	return
}

type PubKey struct {
	Client          iamiface.IAMAPI
	Region          string
	UserID          string
	SecretAccessKey string
	AccessKeyId     string
	SessionToken    string
}

//Retrieves the given user public key id
func (g *PubKey) getPubKey(SshPublicKeyId string) (pubKey string) {
	params := &iam.GetSSHPublicKeyInput{
		Encoding:       aws.String("SSH"),
		SSHPublicKeyId: aws.String(SshPublicKeyId),
		UserName:       aws.String(g.UserID),
	}

	req, resp := g.Client.GetSSHPublicKeyRequest(params)
	req.Send()
	pubKey = *resp.SSHPublicKey.SSHPublicKeyBody
	return
}

//List the given user public keys
func (g *PubKey) listPublicKeys() (pubKeys []*iam.SSHPublicKeyMetadata) {
	param := &iam.ListSSHPublicKeysInput{
		UserName: aws.String(g.UserID),
	}
	req, resp := g.Client.ListSSHPublicKeysRequest(param)
	err := req.Send()
	if err != nil {
		fmt.Printf("%s", err)
		os.Exit(1)
	}
	pubKeys = resp.SSHPublicKeys
	return
}

//Filters only the active user public keys
func (g *PubKey) getActivePubKey(SSHPublicKeys []*iam.SSHPublicKeyMetadata) (sSHPublicKeyID []string) {
	for _, SSHPublicKey := range SSHPublicKeys {
		if *SSHPublicKey.Status == "Active" {
			sSHPublicKeyID = append(sSHPublicKeyID, *SSHPublicKey.SSHPublicKeyId)
		}
	}
	return
}

func main() {

	//CLI menu
	userid := ""
	if os.Args[1] == "--version" {
		fmt.Printf("Authorized Keys Command Version: %s\n", version)
		os.Exit(0)
	} else if len(os.Args) > 1 {
		userid = os.Args[1]
	} else {
		os.Exit(0)
	}

	//Get information from metadata service
	region, instanceID, accountID := ec2Metadata(session.Must(session.NewSession()), &aws.Config{})

	//Create AWS api session
	sess := session.Must(session.NewSession(&aws.Config{Region: aws.String(region)}))

	t := Tag{
		Client:     ec2.New(sess),
		TagName:    "auth-account-arn",
		InstanceId: instanceID,
		Region:     region,
	}

	//Get Auth Account Arn for the EC2 tag
	authAccountArn := t.getTagValue()

	a := AccessKeyIdSecretAccessKeySessionToken{
		Client:         sts.New(sess),
		AuthAccountArn: authAccountArn,
		UserId:         userid,
		AccountID:      accountID,
	}

	//Get temporary credentials
	accessKeyId, secretAccessKey, sessionToken := a.getAccessKeyIdSecretAccessKeySessionToken()

	assumedSess := session.Must(session.NewSession(&aws.Config{
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

	g := PubKey{
		Client:          iam.New(assumedSess),
		Region:          region,
		UserID:          userid,
		SecretAccessKey: secretAccessKey,
		AccessKeyId:     secretAccessKey,
		SessionToken:    sessionToken,
	}

	//Print out the public key/s if there is an active one available
	pubKeys := g.listPublicKeys()
	sshPubKeyIDs := g.getActivePubKey(pubKeys)
	for _, sshPubKeyID := range sshPubKeyIDs {
		if sshPubKeyID != "" {
			fmt.Println(g.getPubKey(sshPubKeyID))
		}
	}
}
