// Copyright 2018 Google Inc. All rights reserved.
// Use of this source code is governed by the Apache 2.0
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"
)

var (
	demo_domain_name  string

	key_ec256   []byte
	certs_ec256 []byte

	key_rsa   []byte
	certs_rsa []byte
	
	key_ec256_invalid   []byte
	certs_ec256_invalid []byte
	
	old_ocsp  []byte
	origin_trial_token string
)

type Config struct {
	EC256KeyFile    string `json:"ec256_key_file"`
	EC256CertFile   string `json:"ec256_cert_file"`
	RSAKeyFile      string `json:"rsa_key_file"`
	RSACertFile     string `json:"rsa_cert_file"`
	EC256InvalidKeyFile    string `json:"ec256_invalid_key_file"`
	EC256InvalidCertFile   string `json:"ec256_invalid_cert_file"`
	
	OldOCSPFile   string `json:"old_ocsp_file"`
	OriginTrialToken string `json:"origin_trial_token"`
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

	key_ec256, _ = ioutil.ReadFile(config.EC256KeyFile)
	certs_ec256, _ = ioutil.ReadFile(config.EC256CertFile)
	key_rsa, _ = ioutil.ReadFile(config.RSAKeyFile)
	certs_rsa, _ = ioutil.ReadFile(config.RSACertFile)
	key_ec256_invalid, _ = ioutil.ReadFile(config.EC256InvalidKeyFile)
	certs_ec256_invalid, _ = ioutil.ReadFile(config.EC256InvalidCertFile)

	demo_domain_name, err = getSubjectCommonName(certs_ec256)
	if err != nil {
		fmt.Println(err.Error())
	}

	old_ocsp, _ = ioutil.ReadFile(config.OldOCSPFile)
	origin_trial_token = config.OriginTrialToken
}

func main() {
	http.HandleFunc("/cert/", certHandler)
	http.HandleFunc("/sxg/", signedExchangeHandler)
	http.HandleFunc("/", defaultHandler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
		log.Printf("Defaulting to port %s", port)
	}

	log.Printf("Listening on port %s", port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", port), nil))
}

func defaultHandler(w http.ResponseWriter, r *http.Request) {
	t := template.Must(template.ParseFiles("templates/index.html"))

	type Data struct {
		Host string
		SXGs []string
	}
	data := Data {
		Host: r.Host,
		SXGs: []string{
			"hello_ec.sxg",
			"404_cert_url.sxg",
			"sha256_mismatch.sxg",
			"expired.sxg",
			"expired_cert.sxg",
			"invalid_validity_url.sxg",
			"old_ocsp.sxg",
			"nested_sxg.sxg",
			"fallback_to_outer_url.sxg",
		},
	}

	if err := t.ExecuteTemplate(w, "index.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
