package main

import (
	"fmt"
	"os"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
)

type awsCredentials struct {
	AccessKeyID     string
	SecretAccessKey string
	MfaSerial       string
	SessionToken    string
	Expiration      *time.Time
}

func newStsCredsWithMFA(config *aws.Config, serial string, tokenDuration int64) (*awsCredentials, error) {
	sess := session.Must(session.NewSession(config))
	token, err := prompt("AWS MFA code: ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get token from stdin: %v\n", err.Error())
		return nil, err
	}
	svc := sts.New(sess)
	sessTokenInput := &sts.GetSessionTokenInput{
		SerialNumber:    aws.String(serial),
		TokenCode:       aws.String(token),
		DurationSeconds: aws.Int64(tokenDuration),
	}
	sessTokenOutput, err := svc.GetSessionToken(sessTokenInput)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get session token: %v\n", err.Error())
		return nil, err
	}

	tmpCreds := &awsCredentials{
		AccessKeyID:     *sessTokenOutput.Credentials.AccessKeyId,
		SecretAccessKey: *sessTokenOutput.Credentials.SecretAccessKey,
		SessionToken:    *sessTokenOutput.Credentials.SessionToken,
		Expiration:      sessTokenOutput.Credentials.Expiration,
	}
	return tmpCreds, nil
}

func assumeRole(sess *session.Session, roleArn string) (*awsCredentials, error) {
	roleCreds := stscreds.NewCredentials(sess, roleArn)
	tmpCredsVal, err := roleCreds.Get()
	if err != nil {
		return nil, err
	}

	creds := &awsCredentials{
		AccessKeyID:     tmpCredsVal.AccessKeyID,
		SecretAccessKey: tmpCredsVal.SecretAccessKey,
		SessionToken:    tmpCredsVal.SessionToken,
	}

	return creds, nil
}
