package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Printf("Usage: %s <host:port>\n", os.Args[0])
		os.Exit(-1)
	}

	conn, err := tls.Dial("tcp", os.Args[1], &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		log.Fatalf("failed to connect: %v\n", err.Error())
	}

	cstate := conn.ConnectionState()
	conn.Close()

	switch cstate.Version {
	case tls.VersionTLS12:
		fmt.Print("TLS1.2/")
	case tls.VersionTLS11:
		fmt.Print("TLS1.1/")
	case tls.VersionTLS10:
		fmt.Print("TLS1.0/")
	case tls.VersionSSL30:
		fmt.Print("SSL3.0/")
	default:
		log.Fatalf("unsupported TLS version: %d\n", cstate.Version)
	}

	switch cstate.CipherSuite {
	case tls.TLS_RSA_WITH_RC4_128_SHA:
		fmt.Println("TLS_RSA_WITH_RC4_128_SHA")
	case tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:
		fmt.Println("TLS_RSA_WITH_3DES_EDE_CBC_SHA")
	case tls.TLS_RSA_WITH_AES_128_CBC_SHA:
		fmt.Println("TLS_RSA_WITH_AES_128_CBC_SHA")
	case tls.TLS_RSA_WITH_AES_256_CBC_SHA:
		fmt.Println("TLS_RSA_WITH_AES_256_CBC_SHA")
	case tls.TLS_RSA_WITH_AES_128_CBC_SHA256:
		fmt.Println("TLS_RSA_WITH_AES_128_CBC_SHA256")
	case tls.TLS_RSA_WITH_AES_128_GCM_SHA256:
		fmt.Println("TLS_RSA_WITH_AES_128_GCM_SHA256")
	case tls.TLS_RSA_WITH_AES_256_GCM_SHA384:
		fmt.Println("TLS_RSA_WITH_AES_256_GCM_SHA384")
	case tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:
		fmt.Println("TLS_ECDHE_ECDSA_WITH_RC4_128_SHA")
	case tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
		fmt.Println("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA")
	case tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
		fmt.Println("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA")
	case tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:
		fmt.Println("TLS_ECDHE_RSA_WITH_RC4_128_SHA")
	case tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:
		fmt.Println("TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA")
	case tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
		fmt.Println("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA")
	case tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
		fmt.Println("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA")
	case tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
		fmt.Println("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256")
	case tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
		fmt.Println("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256")
	case tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
		fmt.Println("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
	case tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
		fmt.Println("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256")
	case tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
		fmt.Println("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")
	case tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
		fmt.Println("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384")
	case tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305:
		fmt.Println("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305")
	case tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305:
		fmt.Println("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305")
	default:
		log.Fatalf("unknown ciphersuite: %d\n", cstate.CipherSuite)
	}

	for k, v := range cstate.PeerCertificates {
		fmt.Printf("\nCertificate[%d]\n", k)
		fmt.Printf("Subject:\t%s\n", v.Subject.CommonName)
		fmt.Printf("Issuer:\t\t%s\n", v.Issuer.CommonName)
		fmt.Printf("Expires:\t%s\n", v.NotAfter.String())
		fmt.Printf("DNS Names:\t%+v\n", v.DNSNames)
		fmt.Printf("IP Addresses:\t%+v\n", v.IPAddresses)
		fmt.Printf("SubjectKeyID:\t%s\n", strings.ToUpper(hex.EncodeToString(v.SubjectKeyId)))
		fmt.Printf("AuthorityKeyID:\t%s\n", strings.ToUpper(hex.EncodeToString(v.AuthorityKeyId)))
	}

	// Validate peer certificate chain
	{
		roots, _ := x509.SystemCertPool()
		ints := x509.NewCertPool()
		for _, v := range cstate.PeerCertificates[1:] {
			ints.AddCert(v)
		}
		opts := x509.VerifyOptions{
			Roots:         roots,
			Intermediates: ints,
		}

		if _, err := cstate.PeerCertificates[0].Verify(opts); err != nil {
			fmt.Printf("Insufficient trust material to validate peer certificate chain: %v\n", err)
		}
	}
}
