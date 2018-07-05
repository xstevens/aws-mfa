package main

import (
	"encoding/json"
	"fmt"
	"os"

	keychain "github.com/keybase/go-keychain"
)

func storeCreds(account string, creds *awsCredentials) error {
	if creds != nil {
		data, err := json.Marshal(creds)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to serialize credentials: %v\n", err)
			return err
		}
		item := keychain.NewGenericPassword("aws-mfa", account, "", data, "")
		err = keychain.AddItem(item)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to store credentials in keychain: %v\n", err)
			return err
		}
	}

	return nil
}

func deleteCreds(account string) error {
	return keychain.DeleteGenericPasswordItem("aws-mfa", account)
}

func loadCreds(account string) (*awsCredentials, error) {
	query := keychain.NewItem()
	query.SetSecClass(keychain.SecClassGenericPassword)
	query.SetService("aws-mfa")
	query.SetAccount(account)
	query.SetReturnData(true)
	results, err := keychain.QueryItem(query)
	if err != nil {
		return nil, err
	}

	// if there are no credentials then return an error
	if len(results) == 0 {
		return nil, fmt.Errorf("No credentials found in keychain")
	}

	creds := awsCredentials{}
	err = json.Unmarshal(results[0].Data, &creds)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to deserialize credentials: %v\n", err)
		return nil, err
	}

	return &creds, nil
}
