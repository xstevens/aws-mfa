package main

import (
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"gopkg.in/alecthomas/kingpin.v2"
)

func must(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v", err)
		os.Exit(1)
	}
}

// The run function runs a command in an environment.
// stdout and stderr are preserved.
func execCommandWithEnv(command []string, env []string) error {
	if len(command) == 0 {
		return fmt.Errorf("No command specified")
	}

	cmd := exec.Command(command[0], command[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = env

	return cmd.Run()
}

func main() {
	app := kingpin.New("aws-mfa", "A command-line wrapper for executing commands with AWS multi-factor authentication.")
	app.HelpFlag.Short('h')
	app.Version("0.1.1")
	app.Author("Xavier Stevens <xavier.stevens@gmail.com>")

	region := app.Flag("region", "AWS Region.").Default(getEnvWithDefault("AWS_DEFAULT_REGION", "us-west-2")).String()
	roleArn := app.Flag("role", "AWS IAM Role.").String()
	tokenDuration := app.Flag("duration", "AWS STS token duration (in seconds).").Default("43200").Int64()
	var command []string
	app.Arg("command", "The command to execute").Required().StringsVar(&command)

	kingpin.MustParse(app.Parse(os.Args[1:]))

	// check if long-term credentials are in keychain and if not prompt user for them
	ltCreds, err := loadCreds("long-term")
	if err != nil {
		accessKeyID, err := getEnvOrPrompt("AWS_ACCESS_KEY_ID", "Enter AWS Access Key ID: ")
		must(err)
		os.Setenv("AWS_ACCESS_KEY_ID", accessKeyID)

		secretAccessKey, err := getEnvOrPrompt("AWS_SECRET_ACCESS_KEY", "Enter AWS Secret Access Key: ")
		must(err)
		os.Setenv("AWS_SECRET_ACCESS_KEY", secretAccessKey)

		mfaSerial, err := getEnvOrPrompt("AWS_MFA_ID", "Enter MFA serial: ")
		must(err)

		// store long term credentials for future to refresh session credentials automatically
		ltCreds = &awsCredentials{
			AccessKeyID:     accessKeyID,
			SecretAccessKey: secretAccessKey,
			MfaSerial:       mfaSerial,
		}
		storeCreds("long-term", ltCreds)
	}

	// check if STS temporary credentials are in keychain and haven't expired
	tmpCreds, err := loadCreds(ltCreds.MfaSerial)
	if err != nil || tmpCreds.Expiration.Before(time.Now()) {
		// if creds have expired we need to remove them from keychain
		// before we can store new ones
		if tmpCreds != nil && tmpCreds.Expiration.Before(time.Now()) {
			deleteCreds(ltCreds.MfaSerial)
		}

		// initiate a session to obtain temporary credentials
		credsVal := &credentials.Value{
			AccessKeyID:     ltCreds.AccessKeyID,
			SecretAccessKey: ltCreds.SecretAccessKey,
		}
		creds := credentials.NewStaticCredentialsFromCreds(*credsVal)
		config := aws.NewConfig().WithRegion(*region).WithCredentials(creds)
		tmpCreds, err = newStsCredsWithMFA(config, ltCreds.MfaSerial, *tokenDuration)
		must(err)

		// store temporary credentials in keychain
		storeCreds(ltCreds.MfaSerial, tmpCreds)
	}

	// if we need to assume a role use the STS temporary creds to do so
	if roleArn != nil && len(*roleArn) > 0 {
		// initiate a session to obtain role credentials
		credsVal := &credentials.Value{
			AccessKeyID:     tmpCreds.AccessKeyID,
			SecretAccessKey: tmpCreds.SecretAccessKey,
			SessionToken:    tmpCreds.SessionToken,
		}
		creds := credentials.NewStaticCredentialsFromCreds(*credsVal)
		config := aws.NewConfig().WithRegion(*region).WithCredentials(creds)
		sess := session.Must(session.NewSession(config))
		tmpCreds, err = assumeRole(sess, *roleArn)
		must(err)
	}

	// set environment variables so temporary credentials override OS environment
	os.Setenv("AWS_ACCESS_KEY_ID", tmpCreds.AccessKeyID)
	os.Setenv("AWS_SECRET_ACCESS_KEY", tmpCreds.SecretAccessKey)
	os.Setenv("AWS_SESSION_TOKEN", tmpCreds.SessionToken)

	// execute command using modified environment
	err = execCommandWithEnv(command, os.Environ())
	must(err)
}
