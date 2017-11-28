package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

func main() {
	host := flag.String("host", "localhost:443", "host:port pair")
	trustAnchors := flag.String("roots", "", "File containing trust anchors in PEM format.  Defaults to system roots.")
	flag.Parse()

	var cstate tls.ConnectionState

	// Get connection state
	{
		conn, err := tls.Dial("tcp", *host, &tls.Config{
			InsecureSkipVerify: true,
		})
		if err != nil {
			fmt.Printf("failed to connect: %v\n", err.Error())
			os.Exit(1)
		}

		cstate = conn.ConnectionState()
		conn.Close()
	}

	// Print negotiated TLS version and ciphersuite.
	{
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
			fmt.Printf("unsupported TLS version: %d\n", cstate.Version)
			os.Exit(1)
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
			fmt.Printf("unknown ciphersuite: %d\n", cstate.CipherSuite)
			os.Exit(1)
		}
	}

	// Print peer certificate chain
	{
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
	}

	// Validate peer certificate chain
	{
		// Develop root certpool
		var roots *x509.CertPool
		var err error
		if *trustAnchors != "" {
			data, err := ioutil.ReadFile(*trustAnchors)
			if err != nil {
				fmt.Printf("Cannot read trust store: %v\n", err)
				os.Exit(1)
			}
			roots = x509.NewCertPool()
			roots.AppendCertsFromPEM(data)
		} else {
			roots, err = x509.SystemCertPool()
			if err != nil {
				fmt.Println("Cannot read system certs")
				os.Exit(1)
			}
		}

		// Develop intermediate certpool
		intermediates := x509.NewCertPool()
		for _, v := range cstate.PeerCertificates[1:] {
			intermediates.AddCert(v)
		}
		opts := x509.VerifyOptions{
			DNSName:       strings.Split(*host, ":")[0],
			Roots:         roots,
			Intermediates: intermediates,
		}

		if _, err := cstate.PeerCertificates[0].Verify(opts); err != nil {
			switch err.(type) {
			case x509.HostnameError:
				fmt.Printf("hostname validation would have failed: %v\n", err)
			case x509.UnknownAuthorityError:
				fmt.Printf("certificate path validation would have failed: %v (%T)\n", err, err)
			default:
				fmt.Printf("Validation failure: %v (%T)\n", err, err)
			}
		}
	}
}
