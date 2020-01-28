package main

import (
	"crypto/tls"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"time"
	"strings"
)
func testgws(ip string, config *ScanConfig, record *ScanRecord) bool {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "443"), config.ScanMaxRTT)
	if err != nil {
		return false
	}
	defer conn.Close()

	var serverName string
	if len(config.ServerName) == 0 {
		serverName = ""
	} else {
		serverName = config.ServerName[rand.Intn(len(config.ServerName))]
	}

	tlscfg := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
		},
		ServerName: serverName,
	}

	tlsconn := tls.Client(conn, tlscfg)
	defer tlsconn.Close()

	tlsconn.SetDeadline(time.Now().Add(config.HandshakeTimeout))
	if err = tlsconn.Handshake(); err != nil {
		return false
	}
	if config.Level > 3 {
		pcs := tlsconn.ConnectionState().PeerCertificates
		if pcs == nil || len(pcs) < 2 {
			return false
		}
		if org := pcs[0].Subject.Organization; len(org) == 0 || org[0] != "Google LLC" {
			return false
		}
	}
	if config.Level > 2 {
		url := "https://" + config.HTTPVerifyHosts[rand.Intn(len(config.HTTPVerifyHosts))]
		req, _ := http.NewRequest(http.MethodGet, url, nil)
		req.Close = true
		c := http.Client{
			Transport: &http.Transport{
				DialTLS: func(network, addr string) (net.Conn, error) { return tlsconn, nil },
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Timeout: config.ScanMaxRTT - time.Since(start),
		}
		resp, _ := c.Do(req)
		if resp == nil || (resp.StatusCode < 200 || resp.StatusCode >= 400) || !strings.Contains(resp.Header.Get("Alt-Svc"), `quic=":443"`) {
			return false
		}
		if resp == nil || (resp.StatusCode < 200 || resp.StatusCode >= 400) {
			return false
		}
		if resp.Body != nil {
			io.Copy(ioutil.Discard, resp.Body)
			resp.Body.Close()
		}
	}

	if rtt := time.Since(start); rtt > config.ScanMinRTT {
		record.RTT += rtt
		return true
	}
	return false
}
