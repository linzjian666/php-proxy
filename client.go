package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/http3"
	"io"
	"log"
	//"net"
	"net/http"
	"reflect"
	//"time"
)

type client struct {
	//global config
	cfg *config
	//http.Transport when connect server
	tr http.RoundTripper
	//tls.Config when connect https server
	tlsconfig *tls.Config
	//http.Client used to connect server
	client *http.Client
	//ca root cert info for middle attack check
	cert *x509.Certificate
}

func (cli *client) Post(url, contentType string, body io.Reader) (resp *http.Response, err error) {
	req, err := http.NewRequest(http.MethodPost, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	if cli.cfg.Sni != "" {
		if req.URL.Port() == "" {
			req.Host = cli.cfg.Sni
		} else {
			req.Host = cli.cfg.Sni + ":" + req.URL.Port()
		}
	}
	if cli.cfg.Debug == true {
		for k, v := range req.Header {
			log.Print(k + ": " + v[0])
		}
	}
	return cli.client.Do(req)
	//return cli.client.Post(url, contentType, body)
}

func (cli *client) Do(req *http.Request) (resp *http.Response, err error) {
	if req == nil {
		log.Printf("POST Request == nil")
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	if cli.cfg.Sni != "" {
		if req.URL.Port() == "" {
			req.Host = cli.cfg.Sni
		} else {
			req.Host = cli.cfg.Sni + ":" + req.URL.Port()
		}
	}
	if cli.cfg.Debug == true {
		for k, v := range req.Header {
			for _, value := range v {
				log.Print(k + ": " + value)
			}
		}
	}
	resp, err = cli.client.Do(req)
	if err != nil {
		cli.tr.(*http3.RoundTripper).Close()
		resp, err = cli.client.Do(req)
	}
	return resp, err
}

func (cli *client) init_client() {
	//tls config
	cli.tlsconfig = &tls.Config{
		InsecureSkipVerify: cli.cfg.Insecure,
		VerifyConnection:   cli.VerifyConnection,
	}
	if cli.cfg.Insecure == true {
		cli.tlsconfig.VerifyConnection = nil
	}
	if cli.cfg.Sni != "" {
		cli.tlsconfig.ServerName = cli.cfg.Sni
	}
	//tr http.client default tr + tlsconfig
	/*
		cli.tr = &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			TLSClientConfig:       cli.tlsconfig,
		}*/
	var qconf quic.Config
	qconf.KeepAlive = true
	//qconf.MaxIdleTimeout = cli.tr.IdleConnTimeout
	cli.tr = &http3.RoundTripper{TLSClientConfig: cli.tlsconfig, QuicConfig: &qconf}
	//
	cli.client = &http.Client{
		Transport: cli.tr,
	}
}
func (cli *client) VerifyConnection(cs tls.ConnectionState) error {
	//
	cert := cs.PeerCertificates[0]
	if reflect.DeepEqual(cert, cli.cert) {
		return errors.New("This is a middle attack server using Php-Proxy CA")
	} else {
		cli.tlsconfig.VerifyConnection = nil
		return nil
	}
}
