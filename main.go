// Copyright 2018 Google Inc. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/s3"
)

var (
	vaultAddr     string
	checkInterval string
	s3BucketName  string
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
	Keys       []string `json:"keys"`
	KeysBase64 []string `json:"keys_base64"`
	RootToken  string   `json:"root_token"`
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

	vaultAddr = os.Getenv("VAULT_ADDR")
	if vaultAddr == "" {
		vaultAddr = "https://127.0.0.1:8200"
	}

	checkInterval = os.Getenv("CHECK_INTERVAL")
	if checkInterval == "" {
		checkInterval = "10"
	}

	i, err := strconv.Atoi(checkInterval)
	if err != nil {
		log.Fatalf("CHECK_INTERVAL is invalid: %s", err)
	}

	checkIntervalDuration := time.Duration(i) * time.Second

	s3BucketName = os.Getenv("S3_BUCKET_NAME")
	if s3BucketName == "" {
		log.Fatal("S3_BUCKET_NAME must be set and not empty")
	}

	kmsKeyId = os.Getenv("KMS_KEY_ID")
	if kmsKeyId == "" {
		log.Fatal("KMS_KEY_ID must be set and not empty")
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
			log.Println("Vault is initialized and unsealed.")
			os.Exit(0)
		case 429:
			log.Println("Vault is unsealed and in standby mode.")
			os.Exit(0)
		case 501:
			log.Println("Vault is not initialized. Initializing and unsealing...")
			initialize()
			os.Exit(0)
		case 503:
			log.Println("Vault is initialized and sealed.")
			os.Exit(0)
		default:
			log.Printf("Vault is in an unknown state. Status code: %d", response.StatusCode)
		}

		log.Printf("Next check in %s", checkIntervalDuration)
		time.Sleep(checkIntervalDuration)
	}
}

func initialize() {
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

	log.Println("Encrypting unseal keys and the root token and uploading to bucket...")

	AWSSession, err := session.NewSession()
	if err != nil {
		log.Println("Error creating session: ", err)
	}

	KMSService := kms.New(AWSSession)
	S3Service := s3.New(AWSSession)

	// Encrypt root token.
	rootTokenEncryptedData, err := KMSService.Encrypt(&kms.EncryptInput{
		KeyId:     aws.String(kmsKeyId),
		Plaintext: []byte(initResponse.RootToken),
	})
	if err != nil {
		log.Println("Error encrypting root token: ", err)
	}

	// Encrypt unseal keys.
	unsealKeysEncryptedData, err := KMSService.Encrypt(&kms.EncryptInput{
		KeyId:     aws.String(kmsKeyId),
		Plaintext: []byte(base64.StdEncoding.EncodeToString(initRequestResponseBody)),
	})
	if err != nil {
		log.Println("Error encrypting unseal keys: ", err)
	}

	// Save the encrypted root token.
	rootTokenPutRequest := &s3.PutObjectInput{
		Body:   bytes.NewReader(rootTokenEncryptedData.CiphertextBlob),
		Bucket: aws.String(s3BucketName),
		Key:    aws.String("root-token.json.enc"),
	}

	_, err = S3Service.PutObject(rootTokenPutRequest)
	if err != nil {
		log.Printf("Cannot write root token to bucket s3://%s/%s: %s", s3BucketName, "root-token.json.enc", err)
	} else {
		log.Printf("Root token written to s3://%s/%s", s3BucketName, "root-token.json.enc")
	}

	// Save the encrypted unseal keys.
	unsealKeysEncryptRequest := &s3.PutObjectInput{
		Body:   bytes.NewReader(unsealKeysEncryptedData.CiphertextBlob),
		Bucket: aws.String(s3BucketName),
		Key:    aws.String("unseal-keys.json.enc"),
	}

	_, err = S3Service.PutObject(unsealKeysEncryptRequest)
	if err != nil {
		log.Printf("Cannot write unseal keys to bucket s3://%s/%s: %s", s3BucketName, "unseal-keys.json.enc", err)
	} else {
		log.Printf("Unseal keys written to s3://%s/%s", s3BucketName, "unseal-keys.json.enc")
	}

	log.Println("Initialization complete.")
}