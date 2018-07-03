package main

import (
	"fmt"
	"os"
)

func getEnvWithDefault(key string, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func getEnvOrPrompt(key string, promptTxt string) (string, error) {
	if value, ok := os.LookupEnv(key); ok {
		return value, nil
	}

	return prompt(promptTxt)
}

func prompt(promptTxt string) (string, error) {
	var val string
	fmt.Print(promptTxt)
	_, err := fmt.Scanln(&val)
	return val, err
}
