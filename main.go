package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"io/ioutil"
	"net/http"

	"epay.api.go/common/smt"
	"github.com/smallnest/goreq"
)

//apiclient_cert is test from wx sample
func main() {
	var (
		certFile = flag.String("cert", "./cert/apiclient_cert.pem", "A PEM eoncoded certificate file.")
		keyFile  = flag.String("key", "./cert/apiclient_key.pem", "A PEM encoded private key file.")
		//caFile   = flag.String("CA", "./cert/rootca.pem", "A PEM eoncoded CA's certificate file.")
	)
	if t, err := CertTransport(certFile, keyFile, nil); err == nil {
		ReqXmlCert(t)
	}

	//ReqXml()
}

func CertTransport(certFile *string, keyFile *string, caFile *string) (transport *http.Transport, err error) {
	flag.Parse()
	// Load client cert
	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		return nil, err
	}

	var caCertPool *(x509.CertPool)
	if caFile != nil {
		// Load CA cert
		caCert, err := ioutil.ReadFile(*caFile)
		if err != nil {
			return nil, err
		}
		caCertPool = x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
	}

	// Setup HTTPS client
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}
	tlsConfig.BuildNameToCertificate()
	return &http.Transport{TLSClientConfig: tlsConfig}, nil
}

//request with cert
func ReqXmlCert(transport *http.Transport) {

	xmldata := `
	<xml><appid>xiaomiao</appid></xml>
	`
	var reqNew = goreq.New()

	reqNew.Transport = transport
	reqNew.Client = &http.Client{Transport: transport}

	req, body, err := reqNew.Post("https://api.mch.weixin.qq.com/secapi/pay/refund").ContentType("xml").SendRawString(xmldata).End()
	if req.StatusCode == http.StatusOK {
		smt.Debug.Println("\n body:", body)
	}
	smt.Debug.Println("\n err:", err)
	smt.Debug.Println("\n req:", req)

}

//request without cert
func ReqXml() {

	xmldata := `
	<xml><appid>xiaomiao</appid></xml>
	`
	req, body, err := goreq.New().Post("https://api.mch.weixin.qq.com/secapi/pay/refund").ContentType("xml").SendRawString(xmldata).End()
	if req.StatusCode == http.StatusOK {
		smt.Debug.Println("\n body:", body)
	}
	smt.Debug.Println("\n err:", err)
	smt.Debug.Println("\n req:", req)

}
