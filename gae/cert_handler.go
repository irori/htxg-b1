// Copyright 2018 Google Inc. All rights reserved.
// Use of this source code is governed by the Apache 2.0
// license that can be found in the LICENSE file.

package main

import (
	"appengine"
	"appengine/urlfetch"
	"bytes"
	"crypto/x509"
	"errors"
	"github.com/WICG/webpackage/go/signedexchange"
	"github.com/WICG/webpackage/go/signedexchange/certurl"
	"golang.org/x/crypto/ocsp"
	"io/ioutil"
	"net/http"
)

func getOCSP(ctx appengine.Context, certs []*x509.Certificate) ([]byte, error) {
	if len(certs) < 2 {
		return nil, errors.New("failed to parse cert")
	}
	cert := certs[0]
	if len(cert.OCSPServer) == 0 {
		return nil, errors.New("No OCSPServer")
	}
	ocspUrl := cert.OCSPServer[0]
	issuer := certs[1]

	buffer, err := ocsp.CreateRequest(cert, issuer, &ocsp.RequestOptions{})
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequest("POST", ocspUrl, bytes.NewReader(buffer))
	if err != nil {
		return nil, err
	}
	request.Header.Add("Content-Type", "application/ocsp-request")
	request.Header.Add("Accept", "application/ocsp-response")
	client := urlfetch.Client(ctx)

	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	output, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	return output, nil
}

func getCertMessage(ctx appengine.Context, pem []byte) ([]byte, error) {
	certs, err := signedexchange.ParseCertificates(pem)
	if err != nil {
		return nil, err
	}
	ocsp, err := getOCSP(ctx, certs)
	if err != nil {
		return nil, err
	}
	// TODO: Support sct
	return certurl.CreateCertChainCBOR(certs, ocsp, nil)
}

func respondWithCertificateMessage(w http.ResponseWriter, r *http.Request, pem []byte) {
	ctx := appengine.NewContext(r)
	message, err := getCertMessage(ctx, pem)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "application/cert-chain+cbor")
	w.Header().Set("Cache-Control", "public, max-age=100")
	w.Write(message)
}

func certHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/cert/ec256" {
		respondWithCertificateMessage(w, r, certs_ec256)
		return
	} else if r.URL.Path == "/cert/rsa" {
		respondWithCertificateMessage(w, r, certs_rsa)
		return
	} else if r.URL.Path == "/cert/ec256_invalid" {
		respondWithCertificateMessage(w, r, certs_ec256_invalid)
		return
	} else if r.URL.Path == "/cert/old_ocsp" {
		parced_certs, err := signedexchange.ParseCertificates(certs_ec256)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		message, err := certurl.CreateCertChainCBOR(parced_certs, old_ocsp, nil)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "application/cert-chain+cbor")
		w.Header().Set("Cache-Control", "public, max-age=100")
		w.Write(message)
		return
	}
	http.Error(w, "Not Found", 404)
}
