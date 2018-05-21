// Copyright 2018 Google Inc. All rights reserved.
// Use of this source code is governed by the Apache 2.0
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"google.golang.org/appengine"
)

var (
	demo_domain_name  string
	demo_appspot_name string

	key_ec256   []byte
	certs_ec256 []byte

	key_rsa   []byte
	certs_rsa []byte
)

type Config struct {
	DemoDomainName  string `json:"demo_domain"`
	DemoAppSpotName string `json:"demo_appspot"`
	EC256KeyName    string `json:"ec256_key_file"`
	EC256CertName   string `json:"ec256_cert_file"`
	RSAKeyName      string `json:"rsa_key_file"`
	RSACertName     string `json:"rsa_cert_file"`
}

func init() {
	var config Config
	file, err := os.Open("config.json")
	defer file.Close()
	if err != nil {
		fmt.Println(err.Error())
	}
	jsonParser := json.NewDecoder(file)
	jsonParser.Decode(&config)

	demo_domain_name = config.DemoDomainName
	demo_appspot_name = config.DemoAppSpotName

	key_ec256, _ = ioutil.ReadFile(config.EC256KeyName)
	certs_ec256, _ = ioutil.ReadFile(config.EC256CertName)
	key_rsa, _ = ioutil.ReadFile(config.RSAKeyName)
	certs_rsa, _ = ioutil.ReadFile(config.RSACertName)
}

func main() {
	http.HandleFunc("/cert/", certHandler)
	http.HandleFunc("/sxg/", signedExchangeHandler)
	appengine.Main()
}

func handle(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "Hello, world!")
}
