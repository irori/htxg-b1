// Copyright 2018 Google Inc. All rights reserved.
// Use of this source code is governed by the Apache 2.0
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto/x509"
	"errors"
	"github.com/WICG/webpackage/go/signedexchange"
	"github.com/WICG/webpackage/go/signedexchange/certurl"
	"net/http"
)

func createCertChainCBOR(certs []*x509.Certificate, ocsp []byte, sct []byte) ([]byte, error) {
	certChain, err := certurl.NewCertChain(certs, ocsp, sct)
	if err != nil {
		return nil, err
	}

	buf := &bytes.Buffer{}
	if err := certChain.Write(buf); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func getCertMessage(pem []byte) ([]byte, error) {
	certs, err := signedexchange.ParseCertificates(pem)
	if err != nil {
		return nil, err
	}
	ocsp, err := certurl.FetchOCSPResponse(certs, true)
	if err != nil {
		return nil, err
	}
	// TODO: Support sct
	return createCertChainCBOR(certs, ocsp, nil)
}

func respondWithCertificateMessage(w http.ResponseWriter, r *http.Request, pem []byte) {
	message, err := getCertMessage(pem)
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
	} else if r.URL.Path == "/cert/ec256_invalid" {
		respondWithCertificateMessage(w, r, certs_ec256_invalid)
		return
	} else if r.URL.Path == "/cert/old_ocsp" {
		parced_certs, err := signedexchange.ParseCertificates(certs_ec256)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		message, err := createCertChainCBOR(parced_certs, old_ocsp, nil)
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

func getSubjectCommonName(pem []byte) (string, error) {
	certs, err := signedexchange.ParseCertificates(pem)
	if err != nil {
		return "", err
	}
	if len(certs) == 0 {
		return "", errors.New("Empty certificate")
	}
	return certs[0].Subject.CommonName, nil
}
