// Copyright 2018 Google Inc. All rights reserved.
// Use of this source code is governed by the Apache 2.0
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/pem"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/WICG/webpackage/go/signedexchange"
	"github.com/WICG/webpackage/go/signedexchange/version"
)

const defaultPayload = `<!DOCTYPE html>
<html>
  <head>
    <title>Hello SignedHTTPExchange</title>
  </head>
  <body>
    <div id="message">
      <h1>Hello SignedHTTPExchange</h1>
    </div>
  </body>
</html>
`

type exchangeParams struct {
	ver               version.Version
	contentUrl        string
	certUrl           string
	validityUrl       string
	pemCerts          []byte
	pemPrivateKey     []byte
	contentType       string
	payload           []byte
	linkPreloadString string
	date              time.Time
}

func createExchange(params *exchangeParams) (*signedexchange.Exchange, error) {
	certUrl, _ := url.Parse(params.certUrl)
	validityUrl, _ := url.Parse(params.validityUrl)
	certs, err := signedexchange.ParseCertificates(params.pemCerts)
	if err != nil {
		return nil, err
	}
	if certs == nil {
		return nil, errors.New("invalid certificate")
	}
	parsedPrivKey, _ := pem.Decode(params.pemPrivateKey)
	if parsedPrivKey == nil {
		return nil, errors.New("invalid private key")
	}
	privkey, err := signedexchange.ParsePrivateKey(parsedPrivKey.Bytes)
	if err != nil {
		return nil, err
	}
	if privkey == nil {
		return nil, errors.New("invalid private key")
	}
	parsedUrl, err := url.Parse(params.contentUrl)
	if err != nil {
		return nil, errors.New("failed to parse URL")
	}
	reqHeader := http.Header{}
	resHeader := http.Header{}
	resHeader.Add("content-type", params.contentType)

	if params.linkPreloadString != "" {
		resHeader.Add("link", params.linkPreloadString)
	}

	e, err := signedexchange.NewExchange(parsedUrl, reqHeader, 200, resHeader, []byte(params.payload))
	if err != nil {
		return nil, err
	}
	if err := e.MiEncodePayload(4096, params.ver); err != nil {
		return nil, err
	}

	s := &signedexchange.Signer{
		Date:        params.date,
		Expires:     params.date.Add(time.Hour * 24),
		Certs:       certs,
		CertUrl:     certUrl,
		ValidityUrl: validityUrl,
		PrivKey:     privkey,
	}
	if s == nil {
		return nil, errors.New("Failed to sign")
	}
	if err := e.AddSignatureHeader(s, params.ver); err != nil {
		return nil, err
	}
	return e, nil
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

func versionFromAcceptHeader(accept string) version.Version {
	for _, t := range strings.Split(accept, ",") {
		switch strings.TrimSpace(t) {
		case "application/signed-exchange;v=b1":
			return version.Version1b1
		case "application/signed-exchange;v=b2":
			return version.Version1b2
		}
	}
	return version.Version1b2
}

func serveExchange(params *exchangeParams, w http.ResponseWriter) {
	e, err := createExchange(params)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	e.Write(w, params.ver)
}

func signedExchangeHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	ver, ok := version.Parse(q.Get("v"))
	if !ok {
		ver = versionFromAcceptHeader(r.Header.Get("accept"))
	}

	w.Header().Set("Content-Type", contentType(ver))

	params := &exchangeParams{
		ver:               ver,
		contentUrl:        "https://" + demo_domain_name + "/hello_ec.html",
		certUrl:           "https://" + demo_appspot_name + "/cert/ec256",
		validityUrl:       "https://" + demo_domain_name + "/cert/null.validity.msg",
		pemCerts:          certs_ec256,
		pemPrivateKey:     key_ec256,
		contentType:       "text/html; charset=utf-8",
		payload:           []byte(defaultPayload),
		linkPreloadString: "",
		date:              time.Now().Add(-time.Second * 10),
	}

	switch r.URL.Path {
	case "/sxg/hello_ec.sxg":
		serveExchange(params, w)
	case "/sxg/hello_rsa.sxg":
		params.contentUrl = "https://" + demo_domain_name + "/hello_rsa.html"
		params.certUrl = "https://" + demo_appspot_name + "/cert/rsa"
		params.pemCerts = certs_rsa
		params.pemPrivateKey = key_rsa
		serveExchange(params, w)
	case "/sxg/404_cert_url.sxg":
		params.certUrl = "https://" + demo_appspot_name + "/cert/not_found"
		serveExchange(params, w)
	case "/sxg/invalid_cert_url.sxg":
		params.certUrl = "https://" + demo_appspot_name + "/cert/ec256_invalid"
		params.pemCerts = certs_ec256_invalid
		params.pemPrivateKey = key_ec256_invalid
		serveExchange(params, w)
	case "/sxg/sha256_missmatch.sxg":
		params.pemCerts = certs_ec256_invalid
		params.pemPrivateKey = key_ec256_invalid
		serveExchange(params, w)
	case "/sxg/expired.sxg":
		params.date = time.Now().Add(-time.Hour * 240)
		serveExchange(params, w)
	case "/sxg/invalid_validity_url.sxg":
		params.validityUrl = "https://invalid." + demo_domain_name + "/cert/null.validity.msg"
		serveExchange(params, w)
	case "/sxg/old_ocsp.sxg":
		params.certUrl = "https://" + demo_appspot_name + "/cert/old_ocsp"
		serveExchange(params, w)
	case "/sxg/nested_sxg.sxg":
		var buf bytes.Buffer
		sxg, err := createExchange(params)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := sxg.Write(&buf, params.ver); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		params.contentUrl = "https://" + demo_domain_name + "/hello_ec.sxg"
		params.contentType = contentType(params.ver)
		params.payload = buf.Bytes()
		serveExchange(params, w)

	default:
		http.Error(w, "signedExchangeHandler", 404)
	}
}
