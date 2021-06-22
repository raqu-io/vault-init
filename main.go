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
	SecretShares    int `json:"secret_shares"`
	SecretThreshold int `json:"secret_threshold"`
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
		case 429:
			log.Println("Vault is unsealed and in standby mode.")
		case 501:
			log.Println("Vault is not initialized. Initializing and unsealing...")
			initialize()
			unseal()
		case 503:
			log.Println("Vault is sealed. Unsealing...")
			unseal()
		default:
			log.Printf("Vault is in an unknown state. Status code: %d", response.StatusCode)
		}

		log.Printf("Next check in %s", checkIntervalDuration)
		time.Sleep(checkIntervalDuration)
	}
}

func initialize() {
	initRequest := InitRequest{
		SecretShares:    5,
		SecretThreshold: 3,
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

func unseal() {

	AWSSession, err := session.NewSession()
	if err != nil {
		log.Println("Error creating session: ", err)
	}

	KMSService := kms.New(AWSSession)
	S3Service := s3.New(AWSSession)

	unsealKeysRequest := &s3.GetObjectInput{
		Bucket: aws.String(s3BucketName),
		Key:    aws.String("unseal-keys.json.enc"),
	}

	unsealKeysEncryptedObject, err := S3Service.GetObject(unsealKeysRequest)
	if err != nil {
		log.Println(err)
		return
	}

	unsealKeysEncryptedObjectData, err := ioutil.ReadAll(unsealKeysEncryptedObject.Body)
	if err != nil {
		log.Println(err)
	}

	unsealKeysData, err := KMSService.Decrypt(&kms.DecryptInput{
		CiphertextBlob: unsealKeysEncryptedObjectData,
	})
	if err != nil {
		log.Println(err)
		return
	}

	var initResponse InitResponse

	unsealKeysPlaintext, err := base64.StdEncoding.DecodeString(string(unsealKeysData.Plaintext))
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
