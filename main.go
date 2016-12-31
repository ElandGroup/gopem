package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"goRequest/logHelper"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/smallnest/goreq"
)

//apiclient_cert is test from wx sample
func main() {
	var (
		certFile = flag.String("cert", "./cert/apiclient_cert.pem", "A PEM eoncoded certificate file.")
		keyFile  = flag.String("key", "./cert/apiclient_key.pem", "A PEM encoded private key file.")
		caFile   = flag.String("CA", "./cert/rootca.pem", "A PEM eoncoded CA's certificate file.")
	)

	ReqXmlCert(CertTransport(certFile, keyFile, caFile))

	//ReqXml()
}

func CertTransport(certFile *string, keyFile *string, caFile *string) *http.Transport {
	flag.Parse()
	// Load client cert
	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Fatal(err)
	}

	// Load CA cert
	caCert, err := ioutil.ReadFile(*caFile)
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Setup HTTPS client
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}
	tlsConfig.BuildNameToCertificate()
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	return transport
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
		logHelper.Debug.Println("\n body:", body)
	}
	logHelper.Debug.Println("\n err:", err)
	logHelper.Debug.Println("\n req:", req)

}

//request without cert
func ReqXml() {

	xmldata := `
	<xml><appid>xiaomiao</appid></xml>
	`
	req, body, err := goreq.New().Post("https://api.mch.weixin.qq.com/secapi/pay/refund").ContentType("xml").SendRawString(xmldata).End()
	if req.StatusCode == http.StatusOK {
		logHelper.Debug.Println("\n body:", body)
	}
	logHelper.Debug.Println("\n err:", err)
	logHelper.Debug.Println("\n req:", req)

}
