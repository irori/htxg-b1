// Copyright 2018 Google Inc. All rights reserved.
// Use of this source code is governed by the Apache 2.0
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"
)

var (
	httpsFlag = flag.Bool("https", false, "Serve over HTTPS")

	demo_domain_name  string

	key_ec256   []byte
	certs_ec256 []byte

	key_ec256_invalid   []byte
	certs_ec256_invalid []byte
	
	old_ocsp  []byte
)

type Config struct {
	EC256KeyFile    string `json:"ec256_key_file"`
	EC256CertFile   string `json:"ec256_cert_file"`
	EC256InvalidKeyFile    string `json:"ec256_invalid_key_file"`
	EC256InvalidCertFile   string `json:"ec256_invalid_cert_file"`
	
	OldOCSPFile   string `json:"old_ocsp_file"`
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
	key_ec256_invalid, _ = ioutil.ReadFile(config.EC256InvalidKeyFile)
	certs_ec256_invalid, _ = ioutil.ReadFile(config.EC256InvalidCertFile)

	demo_domain_name, err = getSubjectCommonName(certs_ec256)
	if err != nil {
		fmt.Println(err.Error())
	}

	old_ocsp, _ = ioutil.ReadFile(config.OldOCSPFile)
}

func main() {
	flag.Parse()

	http.HandleFunc("/cert/", certHandler)
	http.HandleFunc("/sxg/", signedExchangeHandler)
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	http.HandleFunc("/", defaultHandler)

	port := os.Getenv("PORT")
	if port == "" {
		if *httpsFlag {
			port = "8443"
		} else {
			port = "8080"
		}
	}

	log.Printf("Listening on port %s", port)
	if *httpsFlag {
		log.Fatal(http.ListenAndServeTLS(fmt.Sprintf(":%s", port), "cert.pem", "key.pem", nil))
	} else {
		log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", port), nil))
	}
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
			"fallback_test.sxg",
			"404_cert_url.sxg",
			"sha256_mismatch.sxg",
			"expired.sxg",
			"expired_cert.sxg",
			"invalid_validity_url.sxg",
			"old_ocsp.sxg",
			"nested_sxg.sxg",
			"inner-url-utf8-bom.sxg",
			"utf8-inner-url.sxg",
			"invalid-utf8-inner-url.sxg",
			"fallback_to_outer_url.sxg",
			"response_not_cacheable.sxg",
			"no-variant-key.sxg",
			"variant-en.sxg",
			"variant-fr.sxg",
			"gzip-inner-encoding.sxg",
			"merkle-integrity-error.sxg",
		},
	}

	if err := t.ExecuteTemplate(w, "index.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
