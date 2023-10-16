package examples

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log"
	"net"
	"strings"
	"testing"

	"github.com/go-resty/resty/v2"
)

// Example about ssl
func TestSkipSsl(t *testing.T) {
	// 1. create tls test server
	ts := createHttpbinServer(2)
	defer ts.Close()

	client := resty.New()

	// 2. fake CA certificate
	// client.SetRootCertificate("conf/rootCA.crt")

	// 3. skip ssl
	client = client.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})

	// 4. send get request
	resp, err := client.R().Get(ts.URL + "/get?a=1")
	if err != nil {
		t.Fatal(err)
	}
	if string(resp.Body()) == "" {
		t.Fatal(string(resp.Body()))
	}
}

func TestSslSkipViaTransport(t *testing.T) {
	// 1. create tls test server
	ts := createHttpbinServer(2)
	defer ts.Close()

	client := resty.New()

	// 3. skip ssl & proxy connect
	tsp,_ := client.Transport()
	_ = tsp
	tsp.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		// not connect to a proxy server,, keep pathname only
		return net.Dial("tcp", ts.URL[strings.LastIndex(ts.URL, "/")+1:])
	}
	tsp.TLSClientConfig = &tls.Config{
		InsecureSkipVerify: true,
	}

	// 4. send get request
	resp, err := client.R().Get(ts.URL + "/get?a=1")
	if err != nil {
		t.Fatal(err)
	}
	if string(resp.Body()) == "" {
		t.Fatal(string(resp.Body()))
	}
}

func TestSslCertSelf(t *testing.T) {
	// 1. create tls test server
	ts := createHttpbinServer(1)
	defer ts.Close()

	client := resty.New()
	// 2. certs
	certs := x509.NewCertPool()
	for _, c := range ts.TLS.Certificates {
		roots, err := x509.ParseCertificates(c.Certificate[len(c.Certificate)-1])
		if err != nil {
			log.Fatalf("error parsing server's root cert: %v", err)
		}
		for _, root := range roots {
			certs.AddCert(root)
		}
	}

	// 3. 代替 client.SetRootCertificate("tmp/ca.crt")
	// 3. with RootCAs & proxy connect
	tsp,_ := client.Transport()
	tsp.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		// not connect to a proxy server,, keep pathname only
		return net.Dial("tcp", ts.URL[strings.LastIndex(ts.URL, "/")+1:])
	}
	tsp.TLSClientConfig = &tls.Config{
		// InsecureSkipVerify: true,
		RootCAs: certs,
	}

	// 4. send get request
	resp, err := client.R().Get(ts.URL + "/get?a=1")
	if err != nil {
		t.Fatal(err)
	}
	if string(resp.Body()) == "" {
		t.Fatal(string(resp.Body()))
	}
}

// go test -timeout 6000s -run '^TesSslCertCustom$'   github.com/ahuigo/requests/v2/examples -v -httptest.serve=127.0.0.1:443
func TesSslCertCustom(t *testing.T) {
	// 1. create tls test server
	ts := createHttpbinServer(2)
	defer ts.Close()

	client := resty.New()


	// 2. fake CA or self-signed certificate like nginx.crt
	client.SetRootCertificate("../conf/nginx.crt")
	tsp,_ := client.Transport()
	tsp.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		// not connect to a proxy server,, keep pathname only
		return net.Dial("tcp", ts.URL[strings.LastIndex(ts.URL, "/")+1:])
	}

	url := strings.Replace(ts.URL, "127.0.0.1", "local.self", 1) + "/get?a=1"
	t.Log(url)
	// time.Sleep(10 * time.Minute)
	// 4. send get request
	resp, err := client.R().Get(url)
	if err != nil {
		t.Fatal(err)
	}
	if string(resp.Body()) == "" {
		t.Fatal(string(resp.Body()))
	}
}
