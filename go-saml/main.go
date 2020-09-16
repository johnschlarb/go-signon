// https://github.com/russellhaering/gosaml2/blob/master/s2example/demo.go
// https://godoc.org/github.com/russellhaering/gosaml2

package main

import (
	"crypto/x509"
	"fmt"
	"net/http"

	"io/ioutil"

	"encoding/base64"
	"encoding/xml"

	saml2 "github.com/russellhaering/gosaml2"
	"github.com/russellhaering/gosaml2/types"
	dsig "github.com/russellhaering/goxmldsig"
)

var (
	idpMetadataURL = "https://dev-761106.okta.com/app/exksqu7qnarRpx47W4x6/sso/saml/metadata"
   port = ":32768"
	sp *saml2.SAMLServiceProvider
)

func main() {
	res, err := http.Get(idpMetadataURL)
	if err != nil {
		panic(err)
	}

	rawMetadata, err := ioutil.ReadAll(res.Body)
	if err != nil {
		panic(err)
	}

	metadata := &types.EntityDescriptor{}
	err = xml.Unmarshal(rawMetadata, metadata)
	if err != nil {
		panic(err)
	}

	certStore := dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{},
	}

	for _, kd := range metadata.IDPSSODescriptor.KeyDescriptors {
		for idx, xcert := range kd.KeyInfo.X509Data.X509Certificates {
			if xcert.Data == "" {
				panic(fmt.Errorf("metadata certificate(%d) must not be empty", idx))
			}
			certData, err := base64.StdEncoding.DecodeString(xcert.Data)
			if err != nil {
				panic(err)
			}

			idpCert, err := x509.ParseCertificate(certData)
			if err != nil {
				panic(err)
			}

			certStore.Roots = append(certStore.Roots, idpCert)
		}
	}

	// We sign the AuthnRequest with a random key because Okta doesn't seem
	// to verify these.
	randomKeyStore := dsig.RandomKeyStoreForTest()

	sp = &saml2.SAMLServiceProvider{
		IdentityProviderSSOURL:      metadata.IDPSSODescriptor.SingleSignOnServices[0].Location,
		IdentityProviderIssuer:      metadata.EntityID,
		ServiceProviderIssuer:       "http://example.com/saml/acs/example",
		AssertionConsumerServiceURL: "https://www.gapinball.com/_saml_callback",
		SignAuthnRequests:           true,
		AudienceURI:                 "www.gapinball.com",
		IDPCertificateStore:         &certStore,
		SPKeyStore:                  randomKeyStore,
	}

	http.HandleFunc("/blog/", blogHandler)
   http.HandleFunc("/_saml_callback", callbackHandler)
	fmt.Printf("Listening on port %s\n\n", port)
	if err = http.ListenAndServe(port, nil); err != nil {
		panic(err)
	}
}

func callbackHandler(rw http.ResponseWriter, req *http.Request) {
	println("Handling SAML Callback")
	err := req.ParseForm()
	if err != nil {
		println("Can't parse form")
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	assertionInfo, err := sp.RetrieveAssertionInfo(req.FormValue("SAMLResponse"))
	if err != nil {
		fmt.Printf("Can't get assertion info: ", err.Error())
		rw.WriteHeader(http.StatusForbidden)
		return
	}

	if assertionInfo.WarningInfo.InvalidTime {
		println("Invalid Time")
		rw.WriteHeader(http.StatusForbidden)
		return
	}

	if assertionInfo.WarningInfo.NotInAudience {
		println("Not in Audience")
		rw.WriteHeader(http.StatusForbidden)
		return
	}

	fmt.Fprintf(rw, "NameID: %s\n", assertionInfo.NameID)

	fmt.Fprintf(rw, "Assertions:\n")

	for key, val := range assertionInfo.Values {
		fmt.Fprintf(rw, "  %s: %+v\n", key, val)
	}

	fmt.Fprintf(rw, "\n")
	fmt.Fprintf(rw, "Warnings:\n")
	fmt.Fprintf(rw, "%+v\n", assertionInfo.WarningInfo)

	fmt.Fprintf(rw, "\nRelay State = %s\n", req.FormValue("RelayState"))
}

func blogHandler(rw http.ResponseWriter, req *http.Request) {

	fmt.Printf("\n\n Got a request, path = %s\n\n", req.URL.Path)
	// include the request URL path as the relayState
	authURL, err := sp.BuildAuthURL(req.URL.Path)
	if err != nil {
		panic(err)
	}

	println("Redirecting to :\n\n", authURL)
   fmt.Printf("\n\n...with SP ACS URL : %s\n", sp.AssertionConsumerServiceURL)
	http.Redirect(rw, req, authURL, http.StatusFound)
}

