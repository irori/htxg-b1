// Copyright 2018 Google Inc. All rights reserved.
// Use of this source code is governed by the Apache 2.0
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"compress/gzip"
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
	ver           version.Version
	contentUrl    string
	certUrl       string
	validityUrl   string
	pemCerts      []byte
	pemPrivateKey []byte
	contentType   string
	resHeader     http.Header
	payload       []byte
	date          time.Time
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
	privkey, err := signedexchange.ParsePrivateKey(params.pemPrivateKey)
	if err != nil {
		return nil, err
	}
	if privkey == nil {
		return nil, errors.New("invalid private key")
	}
	reqHeader := http.Header{}
	params.resHeader.Add("content-type", params.contentType)
	params.resHeader.Add("timing-allow-origin", "*")

	e := signedexchange.NewExchange(params.ver, params.contentUrl, http.MethodGet, reqHeader, 200, params.resHeader, []byte(params.payload))

	if err := e.MiEncodePayload(4096); err != nil {
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
	if err := e.AddSignatureHeader(s); err != nil {
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
	case version.Version1b3:
		return "application/signed-exchange;v=b3"
	default:
		panic("not reached")
	}
}

func versionFromAcceptHeader(accept string) (version.Version, error) {
	for _, t := range strings.Split(accept, ",") {
		s := strings.TrimSpace(t)
		if strings.HasPrefix(s, "application/signed-exchange;v=b1") {
			return version.Version1b1, nil
		}
		if strings.HasPrefix(s, "application/signed-exchange;v=b2") {
			return version.Version1b2, nil
		}
		if strings.HasPrefix(s, "application/signed-exchange;v=b3") {
			return version.Version1b3, nil
		}
	}
	return "", errors.New("Cannot determine SXG version from Accept: header")
}

func createAndServeExchange(params *exchangeParams, q url.Values, w http.ResponseWriter) {
	e, err := createExchange(params)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	serveExchange(e, q, w)
}

func serveExchange(e *signedexchange.Exchange, q url.Values, w http.ResponseWriter) {
	w.Header().Set("Content-Type", contentType(e.Version))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Timing-Allow-Origin", "*")
	e.Write(w)
}

func signedExchangeHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	ver, ok := version.Parse(q.Get("v"))
	if !ok {
		var err error
		ver, err = versionFromAcceptHeader(r.Header.Get("accept"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	params := &exchangeParams{
		ver:           ver,
		contentUrl:    "https://" + demo_domain_name + "/hello_ec.html",
		certUrl:       "https://" + r.Host + "/cert/ec256",
		validityUrl:   "https://" + demo_domain_name + "/cert/null.validity.msg",
		pemCerts:      certs_ec256,
		pemPrivateKey: key_ec256,
		contentType:   "text/html; charset=utf-8",
		resHeader:     http.Header{},
		payload:       []byte(defaultPayload),
		date:          time.Now().Add(-time.Second * 10),
	}

	switch r.URL.Path {
	case "/sxg/hello_ec.sxg":
		createAndServeExchange(params, q, w)
	case "/sxg/fallback_test.sxg":
		params.contentUrl = "https://" + r.Host + "/static/fallback.html"
		createAndServeExchange(params, q, w)
	case "/sxg/404_cert_url.sxg":
		params.certUrl = "https://" + r.Host + "/cert/not_found"
		createAndServeExchange(params, q, w)
	case "/sxg/expired_cert.sxg":
		params.certUrl = "https://" + r.Host + "/cert/ec256_invalid"
		params.pemCerts = certs_ec256_invalid
		params.pemPrivateKey = key_ec256_invalid
		createAndServeExchange(params, q, w)
	case "/sxg/sha256_mismatch.sxg":
		params.pemCerts = certs_ec256_invalid
		params.pemPrivateKey = key_ec256_invalid
		createAndServeExchange(params, q, w)
	case "/sxg/expired.sxg":
		params.date = time.Now().Add(-time.Hour * 240)
		createAndServeExchange(params, q, w)
	case "/sxg/invalid_validity_url.sxg":
		params.validityUrl = "https://invalid." + demo_domain_name + "/cert/null.validity.msg"
		createAndServeExchange(params, q, w)
	case "/sxg/old_ocsp.sxg":
		params.certUrl = "https://" + r.Host + "/cert/old_ocsp"
		createAndServeExchange(params, q, w)
	case "/sxg/nested_sxg.sxg":
		var buf bytes.Buffer
		sxg, err := createExchange(params)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := sxg.Write(&buf); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		params.contentUrl = "https://" + demo_domain_name + "/hello_ec.sxg"
		params.contentType = contentType(params.ver)
		params.payload = buf.Bytes()
		createAndServeExchange(params, q, w)
	case "/sxg/inner-url-utf8-bom.sxg":
		params.contentUrl = "\xef\xbb\xbf" + params.contentUrl
		createAndServeExchange(params, q, w)
	case "/sxg/utf8-inner-url.sxg":
		params.contentUrl = "https://" + demo_domain_name + "/🌐📦.html"
		createAndServeExchange(params, q, w)
	case "/sxg/invalid-utf8-inner-url.sxg":
		params.contentUrl = "https://" + demo_domain_name + "/\xce\xce\xa9.html"
		createAndServeExchange(params, q, w)
	case "/sxg/fallback_to_outer_url.sxg":
		params.contentUrl = "https://" + r.Host + "/sxg/fallback_to_outer_url.sxg"
		createAndServeExchange(params, q, w)
	case "/sxg/response_not_cacheable.sxg":
		params.resHeader.Add("cache-control", "no-store")
		createAndServeExchange(params, q, w)
	case "/sxg/no-variant-key.sxg":
		params.resHeader.Add("variants-04", "Accept-Language;en;de")
		createAndServeExchange(params, q, w)
	case "/sxg/variant-en.sxg":
		params.resHeader.Add("variants-04", "Accept-Language;en;fr")
		params.resHeader.Add("variant-key-04", "en")
		createAndServeExchange(params, q, w)
	case "/sxg/variant-fr.sxg":
		params.resHeader.Add("variants-04", "Accept-Language;en;fr")
		params.resHeader.Add("variant-key-04", "fr")
		createAndServeExchange(params, q, w)
	case "/sxg/gzip-inner-encoding.sxg":
		var gzbuf bytes.Buffer
		gz := gzip.NewWriter(&gzbuf)
		gz.Write(params.payload)
		gz.Close()
		params.payload = gzbuf.Bytes()
		params.resHeader.Add("content-encoding", "gzip")
		createAndServeExchange(params, q, w)
	case "/sxg/merkle-integrity-error.sxg":
		e, err := createExchange(params)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		e.Payload[len(e.Payload)-1] ^= 0xff
		serveExchange(e, q, w)
	default:
		http.Error(w, "signedExchangeHandler", 404)
	}
}
