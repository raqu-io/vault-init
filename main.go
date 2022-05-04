// Copyright 2018 Google Inc. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go/service/kms"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ssm"
)

var (
	vaultAddr     string
	checkInterval string
	ssmSuffix     string
	ssmKeysPath   string
	ssmTokenPath  string
	httpClient    http.Client
	kmsKeyId      string
)

// InitRequest holds a Vault init request.
type InitRequest struct {
	RecoveryShares    int `json:"recovery_shares"`
	RecoveryThreshold int `json:"recovery_threshold"`
}

// InitResponse holds a Vault init response.
type InitResponse struct {
	Keys       	       []string `json:"keys"`
	KeysBase64         []string `json:"keys_base64"`
	RecoveryKeys       []string `json:"recovery_keys"`
	RecoveryKeysBase64 []string `json:"recovery_keys_base64"`
	RootToken          string   `json:"root_token"`
}

// UnsealRequest holds a Vault unseal request.
type UnsealRequest struct {
	Key   string `json:"key"`
	Reset bool   `json:"reset"`
}

// UnsealResponse holds a Vault unseal response.
type UnsealResponse struct {
	Sealed   bool `json:"sealed"`
	T        int  `json:"t"`
	N        int  `json:"n"`
	Progress int  `json:"progress"`
}

func main() {
	log.Println("Starting the vault-init service...")

	vaultAddr = os.Getenv("VAULT_INIT_VAULT_ADDR")
	if vaultAddr == "" {
		vaultAddr = "https://127.0.0.1:8200"
	}

	checkInterval = os.Getenv("VAULT_INIT_CHECK_INTERVAL")
	if checkInterval == "" {
		checkInterval = "10"
	}

	i, err := strconv.Atoi(checkInterval)
	if err != nil {
		log.Fatalf("CHECK_INTERVAL is invalid: %s", err)
	}

	checkIntervalDuration := time.Duration(i) * time.Second

	ssmSuffix = os.Getenv("VAULT_INIT_SSM_SUFFIX")
	if ssmSuffix == "" {
		log.Fatal("VAULT_INIT_SSM_SUFFIX must be set and not empty")
	}

	ssmKeysPath = "/VAULT/" + ssmSuffix + "/UNSEAL_KEYS"
	ssmTokenPath = "/VAULT/" + ssmSuffix + "/ROOT_TOKEN"

	kmsKeyId = os.Getenv("VAULT_INIT_KMS_KEY_ID")
	if kmsKeyId == "" {
		log.Fatal("VAULT_INIT_KMS_KEY_ID must be set and not empty")
	}

	timeout := 2 * time.Second

	httpClient = http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	for {
		response, err := httpClient.Get(vaultAddr + "/v1/sys/health")
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}

		if err != nil {
			log.Println(err)
			time.Sleep(checkIntervalDuration)
			continue
		}

		switch response.StatusCode {
		case 200:
			log.Println("Vault is initialized and unsealed. Nothing to do")
			os.Exit(0)
		case 429:
			log.Println("Vault is unsealed and in standby mode. Nothing to do")
			os.Exit(0)
		case 501:
			log.Println("Vault is not initialized. Initializing...")
			initialize()
			os.Exit(0)
		case 503:
			log.Println("Vault is initialized and sealed. Nothing to do")
			os.Exit(0)
		default:
			log.Printf("Vault is in an unknown state. Status code: %d", response.StatusCode)
		}

		log.Printf("Next check in %s", checkIntervalDuration)
		time.Sleep(checkIntervalDuration)
	}
}

func initialize() {
	log.Println("Checking permissions on S3 and KMS before initializing")
	AWSSession, err := session.NewSession()
	if err != nil {
		log.Println("Error creating session: ", err)
	}

	KMSService := kms.New(AWSSession)

	_, err = KMSService.Encrypt(&kms.EncryptInput{
		KeyId:     aws.String(kmsKeyId),
		Plaintext: []byte("foobar"),
	})
	if err != nil {
		log.Println("Error with KMS permissions: ", err)
		os.Exit(1)
	}

	// TODO: allow to be set through env
	initRequest := InitRequest{
		RecoveryShares:    5,
		RecoveryThreshold: 3,
	}

	initRequestData, err := json.Marshal(&initRequest)
	if err != nil {
		log.Println(err)
		return
	}

	r := bytes.NewReader(initRequestData)

	request, err := http.NewRequest("PUT", vaultAddr+"/v1/sys/init", r)
	if err != nil {
		log.Println(err)
		return
	}

	response, err := httpClient.Do(request)
	if err != nil {
		log.Println(err)
		return
	}

	initRequestResponseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Println(err)
		return
	}

	if response.StatusCode != 200 {
		log.Printf("init: non 200 status code: %d", response.StatusCode)
		return
	}

	var initResponse InitResponse

	if err := json.Unmarshal(initRequestResponseBody, &initResponse); err != nil {
		log.Println(err)
		return
	}

	log.Println("Encrypting unseal keys and the root token and uploading to ssm...")

	SSMService := ssm.New(AWSSession)

	// Save the encrypted root token.
	rootTokenPutRequest := &ssm.PutParameterInput {
		Name: aws.String(ssmTokenPath),
		Type: aws.String("SecureString"),
		Value: aws.String(string([]byte(initResponse.RootToken))),
		Overwrite: aws.Bool(true),
		KeyId: aws.String(kmsKeyId),
	}

	_, err = SSMService.PutParameter(rootTokenPutRequest)
	if err != nil {
		log.Printf("Cannot write root token to ssm at ssm://%s: %s", ssmTokenPath, err)
	} else {
		log.Printf("Root token written to ssm://%s", ssmTokenPath)
	}

	// Save the encrypted unseal keys.
	unsealKeysEncryptRequest := &ssm.PutParameterInput {
		Name: aws.String(ssmKeysPath),
		Type: aws.String("SecureString"),
		Value: aws.String(base64.StdEncoding.EncodeToString(initRequestResponseBody)),
		Overwrite: aws.Bool(true),
		KeyId: aws.String(kmsKeyId),
	}

	_, err = SSMService.PutParameter(unsealKeysEncryptRequest)
	if err != nil {
		log.Printf("Cannot write unseal keys to ssm at ssm://%s: %s", ssmKeysPath, err)
	} else {
		log.Printf("Unseal keys written to ssm://%s", ssmKeysPath)
	}

	log.Println("Initialization complete.")
}

func unseal() {

	AWSSession, err := session.NewSession()
	if err != nil {
		log.Println("Error creating session: ", err)
	}

	SSMService := ssm.New(AWSSession)

	unsealKeysRequest := &ssm.GetParameterInput{
		Name: aws.String(ssmKeysPath),
		WithDecryption: aws.Bool(true),
	}

	unsealKeysData, err := SSMService.GetParameter(unsealKeysRequest)
	if err != nil {
		log.Printf("Cannot read unseal keys from ssm at ssm://%s: %s", ssmKeysPath, err)
	}

	var initResponse InitResponse

	unsealKeysPlaintext, err := base64.StdEncoding.DecodeString(*unsealKeysData.Parameter.Value)
	if err != nil {
		log.Println(err)
		return
	}

	if err := json.Unmarshal(unsealKeysPlaintext, &initResponse); err != nil {
		log.Println(err)
		return
	}

	for _, key := range initResponse.KeysBase64 {
		done, err := unsealOne(key)
		if done {
			return
		}

		if err != nil {
			log.Println(err)
			return
		}
	}
}

func unsealOne(key string) (bool, error) {
	unsealRequest := UnsealRequest{
		Key: key,
	}

	unsealRequestData, err := json.Marshal(&unsealRequest)
	if err != nil {
		return false, err
	}

	r := bytes.NewReader(unsealRequestData)
	request, err := http.NewRequest(http.MethodPut, vaultAddr+"/v1/sys/unseal", r)
	if err != nil {
		return false, err
	}

	response, err := httpClient.Do(request)
	if err != nil {
		return false, err
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		return false, fmt.Errorf("unseal: non-200 status code: %d", response.StatusCode)
	}

	unsealRequestResponseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return false, err
	}

	var unsealResponse UnsealResponse
	if err := json.Unmarshal(unsealRequestResponseBody, &unsealResponse); err != nil {
		return false, err
	}

	if !unsealResponse.Sealed {
		return true, nil
	}

	return false, nil
}