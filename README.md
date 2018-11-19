# Signed Exchange test server for Google App Engine

## Usage

1. Prepare a certificate and private key pair to use for signing the exchange. See [github.com/WICG/webpackage/go/signedexchange/README.md](https://github.com/WICG/webpackage/tree/master/go/signedexchange) for details.

2. Copy `gae/empty-config.json` to `gae/config.json` and fill in values.

   The following fields are required:

   - `ec256_key_file`: The private key created at step 1.
   - `ec256_cert_file`: The certificate chain created at step 1.

   Example:

   ```json
   {
     "ec256_key_file": "cert/key.pem",
     "ec256_cert_file": "cert/cert-chain.pem",
   }
   ```

3. Deploy the app.

   `gcloud app deploy app.yaml`
