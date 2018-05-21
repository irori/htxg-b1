// Copyright 2018 Google Inc. All rights reserved.
// Use of this source code is governed by the Apache 2.0
// license that can be found in the LICENSE file.

package main

import (
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/nyaxt/webpackage/go/signedexchange"
)

func handleSignedExchangeRequest(w http.ResponseWriter, contentUrl string, certUrlStr string, validityUrlStr string, pemCerts []byte, pemPrivateKey []byte, filename string, linkPreloadString string, date time.Time) {
	payload, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Fprintln(w, "Failed to Readfile")
		return
	}
	certUrl, _ := url.Parse(certUrlStr)
	validityUrl, _ := url.Parse(validityUrlStr)
	certs, err := signedexchange.ParseCertificates(pemCerts)
	if err != nil {
		fmt.Fprintln(w, "Failed to parse certificate")
		return
	}
	if certs == nil {
		fmt.Fprintln(w, "invalid certificate")
		return
	}
	parsedPrivKey, _ := pem.Decode(pemPrivateKey)
	if parsedPrivKey == nil {
		fmt.Fprintln(w, "invalid private key")
		return
	}
	privkey, err := signedexchange.ParsePrivateKey(parsedPrivKey.Bytes)
	if err != nil {
		fmt.Fprintln(w, "failed to parse private key")
		return
	}
	if privkey == nil {
		fmt.Fprintln(w, "invalid private key")
		return
	}
	parsedUrl, err := url.Parse(contentUrl)
	if err != nil {
		fmt.Fprintln(w, "failed to parse URL")
		return
	}
	reqHeader := http.Header{}
	resHeader := http.Header{}
	resHeader.Add("content-type", "text/html; charset=utf-8")

	if linkPreloadString != "" {
		resHeader.Add("link", linkPreloadString)
	}

	e, err := signedexchange.NewExchange(parsedUrl, reqHeader, 200, resHeader, []byte(payload), 4096)
	if err != nil {
		fmt.Fprintln(w, "NewExchange failed")
		return
	}

	s := &signedexchange.Signer{
		Date:        date,
		Expires:     date.Add(time.Hour * 24),
		Certs:       certs,
		CertUrl:     certUrl,
		ValidityUrl: validityUrl,
		PrivKey:     privkey,
	}
	if s == nil {
		fmt.Fprintln(w, "Failed to sing")
		return
	}
	if err := e.AddSignatureHeader(s); err != nil {
		fmt.Fprintln(w, "AddSignatureHeader failed: %s", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/signed-exchange;v=b1")
	if err := signedexchange.WriteExchangeFile(w, e); err != nil {
		fmt.Fprintln(w, "failed to WriteExchangeFile")
		return
	}
}

func signedExchangeHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/sxg/hello_rsa.sxg" {
		handleSignedExchangeRequest(w, "https://"+demo_domain_name+"/hello_rsa.html", "https://"+demo_appspot_name+"/cert/rsa", "https://"+demo_domain_name+"/cert/null.validity.msg", certs_rsa, key_rsa, "hello.html", "", time.Now().Add(-time.Second*10))
		return
	}
	if r.URL.Path == "/sxg/hello_ec.sxg" {
		handleSignedExchangeRequest(w, "https://"+demo_domain_name+"/hello_ec.html", "https://"+demo_appspot_name+"/cert/ec256", "https://"+demo_domain_name+"/cert/null.validity.msg", certs_ec256, key_ec256, "hello.html", "", time.Now().Add(-time.Second*10))
		return
	}
	http.Error(w, "signedExchangeHandler", 404)
}
