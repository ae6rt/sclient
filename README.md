# sclient

Partial implementation of *openssl s_client* in Go.  sclient prints useful information about the peer connection.

## Install 

```bash
$ go get -u github.com/ae6rt/sclient
```

## Run

```bash
$ sclient <host:port>
```

For example

```bash
$ sclient www.google.com:443
TLS1.2/TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256

Certificate[0]
Subject:	www.google.com
Issuer:		Google Internet Authority G2
Expires:	2018-01-24 13:30:00 +0000 UTC
DNS Names:	[www.google.com]
IP Addresses:	[]
SubjectKeyID:	EF43DF45A9C7E5DD1C689620B9751B75658F6B0E
AuthorityKeyID:	4ADD06161BBCF668B576F581B6BB621ABA5A812F

Certificate[1]
Subject:	Google Internet Authority G2
Issuer:		GeoTrust Global CA
Expires:	2018-12-31 23:59:59 +0000 UTC
DNS Names:	[]
IP Addresses:	[]
SubjectKeyID:	4ADD06161BBCF668B576F581B6BB621ABA5A812F
AuthorityKeyID:	C07A98688D89FBAB05640C117DAA7D65B8CACC4E

Certificate[2]
Subject:	GeoTrust Global CA
Issuer:		
Expires:	2018-08-21 04:00:00 +0000 UTC
DNS Names:	[]
IP Addresses:	[]
SubjectKeyID:	C07A98688D89FBAB05640C117DAA7D65B8CACC4E
AuthorityKeyID:	48E668F92BD2B295D747D82320104F3398909FD4
```



