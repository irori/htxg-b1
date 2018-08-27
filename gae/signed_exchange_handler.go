// Copyright 2018 Google Inc. All rights reserved.
// Use of this source code is governed by the Apache 2.0
// license that can be found in the LICENSE file.

package main

import (
	"encoding/pem"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"
	"errors"

	"github.com/WICG/webpackage/go/signedexchange"
	"github.com/WICG/webpackage/go/signedexchange/version"
)

func createExchange(ver version.Version, contentUrl string, certUrlStr string, validityUrlStr string, pemCerts []byte, pemPrivateKey []byte, filename string, linkPreloadString string, date time.Time) (*signedexchange.Exchange, error)  {
	payload, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	certUrl, _ := url.Parse(certUrlStr)
	validityUrl, _ := url.Parse(validityUrlStr)
	certs, err := signedexchange.ParseCertificates(pemCerts)
	if err != nil {
		return nil, err
	}
	if certs == nil {
		return nil,  errors.New("invalid certificate")
	}
	parsedPrivKey, _ := pem.Decode(pemPrivateKey)
	if parsedPrivKey == nil {
		return nil,  errors.New("invalid private key")
	}
	privkey, err := signedexchange.ParsePrivateKey(parsedPrivKey.Bytes)
	if err != nil {
		return nil, err
	}
	if privkey == nil {
		return nil,  errors.New("invalid private key")
	}
	parsedUrl, err := url.Parse(contentUrl)
	if err != nil {
		return nil,  errors.New("failed to parse URL")
	}
	reqHeader := http.Header{}
	resHeader := http.Header{}
	resHeader.Add("content-type", "text/html; charset=utf-8")

	if linkPreloadString != "" {
		resHeader.Add("link", linkPreloadString)
	}

	e, err := signedexchange.NewExchange(parsedUrl, reqHeader, 200, resHeader, []byte(payload))
	if err != nil {
		return nil,  err
	}
	if err := e.MiEncodePayload(4096, ver); err != nil {
		return nil, err
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
		return nil,  errors.New("Failed to sing")
	}
	if err := e.AddSignatureHeader(s, ver); err != nil {
		return nil, err
	}
	return e, nil;
}

func contentType(v version.Version) string {
	switch v {
	case version.Version1b1:
		return "application/signed-exchange;v=b1"
	case version.Version1b2:
		return "application/signed-exchange;v=b2"
	default:
		panic("not reached")
	}
}

func signedExchangeHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	ver, ok := version.Parse(q.Get("v"))
	if !ok {
		ver = version.Version1b2
	}

	w.Header().Set("Content-Type", contentType(ver))
	
	nullValidityUrl := "https://"+demo_domain_name+"/cert/null.validity.msg"
	
	if r.URL.Path == "/sxg/hello_rsa.sxg" {
		e, err := createExchange(ver, "https://"+demo_domain_name+"/hello_rsa.html", "https://"+demo_appspot_name+"/cert/rsa", nullValidityUrl , certs_rsa, key_rsa, "hello.html", "", time.Now().Add(-time.Second*10))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		e.Write(w, ver)
		return
	}
	if r.URL.Path == "/sxg/hello_ec.sxg" {
		e, err := createExchange(ver, "https://"+demo_domain_name+"/hello_ec.html", "https://"+demo_appspot_name+"/cert/ec256", nullValidityUrl, certs_ec256, key_ec256, "hello.html", "", time.Now().Add(-time.Second*10))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		e.Write(w, ver)
		return
	}
	if r.URL.Path == "/sxg/404_cert_url.sxg" {
		e, err := createExchange(ver, "https://"+demo_domain_name+"/hello_ec.html", "https://"+demo_appspot_name+"/cert/not_found", nullValidityUrl, certs_ec256, key_ec256, "hello.html", "", time.Now().Add(-time.Second*10))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		e.Write(w, ver)
		return
	}
	if r.URL.Path == "/sxg/invalid_cert_url.sxg" {
		e, err := createExchange(ver, "https://"+demo_domain_name+"/hello_ec.html", "https://"+demo_appspot_name+"/cert/ec256_invalid", nullValidityUrl, certs_ec256_invalid, key_ec256_invalid, "hello.html", "", time.Now().Add(-time.Second*10))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		e.Write(w, ver)
		return
	}
	if r.URL.Path == "/sxg/sha256_missmatch.sxg" {
		e, err := createExchange(ver, "https://"+demo_domain_name+"/hello_ec.html", "https://"+demo_appspot_name+"/cert/ec256", nullValidityUrl, certs_ec256_invalid, key_ec256_invalid, "hello.html", "", time.Now().Add(-time.Second*10))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		e.Write(w, ver)
		return
	}
	if r.URL.Path == "/sxg/expired.sxg" {
		e, err := createExchange(ver, "https://"+demo_domain_name+"/hello_ec.html", "https://"+demo_appspot_name+"/cert/ec256", nullValidityUrl, certs_ec256, key_ec256, "hello.html", "", time.Now().Add(-time.Hour * 240))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		e.Write(w, ver)
		return
	}
	if r.URL.Path == "/sxg/invalid_validity_url.sxg" {
		invalidValidityUrl := "https://invalid."+demo_domain_name+"/cert/null.validity.msg"
		e, err := createExchange(ver, "https://"+demo_domain_name+"/hello_ec.html", "https://"+demo_appspot_name+"/cert/ec256", invalidValidityUrl, certs_ec256, key_ec256, "hello.html", "", time.Now().Add(-time.Second*10))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		e.Write(w, ver)
		return
	}
	if r.URL.Path == "/sxg/old_ocsp.sxg" {
		e, err := createExchange(ver, "https://"+demo_domain_name+"/hello_ec.html", "https://"+demo_appspot_name+"/cert/old_ocsp", nullValidityUrl, certs_ec256, key_ec256, "hello.html", "", time.Now().Add(-time.Second*10))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		e.Write(w, ver)
		return
	}
	http.Error(w, "signedExchangeHandler", 404)
}
