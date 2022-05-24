package main

import (
	// "acme"

	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/eggsampler/acme/v3"
)

var (
	version   string
	buildtime string
)

var (
	accountFile = "account.json"
	certFile    = "server.pem"
	keyFile     = "server.key"

	// DigiCertProduction that is digicert acme endpoint
	DigiCertProduction = "https://acme.digicert.com/v2/acme/directory/"
	ac                 acme.Client
	aa                 acme.Account
	location           string
)

func main() {

	fmt.Printf("App version: %s, build on %s\n\n", version, buildtime)

	var domains, dir string
	var renew int64
	var issue bool
	flag.StringVar(&domains, "domains", "", "Domains that you wanted to secure, e.g. example.com")
	flag.StringVar(&dir, "dir", "", "Where the directory you wanted to save certificate, e.g. /etc/web/your-domain/")
	flag.Int64Var(&renew, "renew", 3, "Renewal period for certificate, default: 3 days")
	flag.BoolVar(&issue, "issue", false, "Issue the new certificate now, default: false")
	flag.Parse()

	if len(domains) == 0 {
		fmt.Println("Usage: acmex-" + runtime.GOOS + " -domains=example.com -dir=/etc/web/your-domain/ -renew=3 -issue=false")
		flag.PrintDefaults()
		os.Exit(1)
	}

	if len(dir) != 0 {
		switch runtime.GOOS {
		case "linux", "darwin", "freebsd", "solaris":
			location = filepath.Dir(dir+"/") + "/"
		case "windows":
			location = filepath.Dir(dir+`\`) + `\`
		}
		os.Mkdir(location, 0755)
	} else {
		location = ""
	}

	if len(os.Getenv("KID")) <= 0 || len(os.Getenv("HMAC")) <= 0 {
		fmt.Println("The KID and HMAC OS environment variables are required")
		os.Exit(1)
	}

	if _, err := os.ReadFile(location + strings.Split(domains, ",")[0] + "/" + certFile); err != nil && issue == false {
		log.Printf("There's no certificate with domain -> %s, in this directory -> %s \n", domains, location+strings.Split(domains, ",")[0]+"/"+certFile)
		return
	}

	var domain string
	if !strings.Contains(domains, ",") {
		domain = domains
	} else {
		domain = strings.Split(domains, ",")[0]
	}

	log.SetPrefix("[acme for " + domain + "]")
	log.SetFlags(log.LUTC | log.LstdFlags)

	// create a new acme client given a provided (or default) directory url
	// log.Printf("Connecting to acme directory url: %s", DigiCertProduction)
	client, err := acme.NewClient(DigiCertProduction)
	if err != nil {
		log.Fatalf("Error connecting to acme directory: %v", err)
	}

	// attempt to load an existing account from file
	log.Printf("Loading account file %s", location+accountFile)
	account, err := loadAccount(client)
	if err != nil {
		// log.Printf("Error loading existing account: %v", err)
		// if there was an error loading an account, just create a new one
		// log.Printf("Creating new account")
		account, err = createAccount(client)
		if err != nil {
			log.Fatalf("Cannot create the acme account %v, please check the KID and HMAC setting", err)
			return
		}
	}
	log.Printf("Account url: %s", account.URL)

	ac = client
	aa = account

	if issue {
		newCertificate(domains, ac, aa)
		return
	}

	pollInterval := 30 // checking the certificate availability every 30 Seconds
	timerCh := time.Tick(time.Duration(pollInterval) * time.Second)

	for range timerCh {

		switch matchCertificate(strings.Split(domains, ",")[0], renew) {
		case 0:
			newCertificate(domains, ac, aa)
		case 1:
			log.Println("No need to renew the certificate")
		case 2:
			return
		default:
			log.Println("No need to renew the certificate")
		}
	}

	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	quit := false
	for {
		select {
		case s := <-sig:
			log.Printf("Signal (%d) received, stopping", s)
			quit = true
			break
		}
		if quit {
			break
		}
	}
}

func newCertificate(domains string, client acme.Client, account acme.Account) {
	domain := strings.Split(domains, ",")[0]
	os.Mkdir(location+domain, 0755)
	// collect the comma separated domains into acme identifiers

	domainList := strings.Split(domains, ",")
	var ids []acme.Identifier
	for _, domain := range domainList {
		ids = append(ids, acme.Identifier{Type: "dns", Value: domain})
	}

	// create a new order with the acme service given the provided identifiers
	log.Printf("Creating new order for domains: %s", domainList)
	order, err := client.NewOrder(account, ids)
	if err != nil {
		log.Fatalf("Error creating new order: %v", err)
	}
	log.Printf("Order created: %s", order.URL)

	log.Println("order.authenrization length -> ", len(order.Authorizations))
	// loop through each of the provided authorization urls
	for _, authURL := range order.Authorizations {
		// fetch the authorization data from the acme service given the provided authorization url
		log.Printf("Fetching authorization: %s", authURL)
		auth, err := client.FetchAuthorization(account, authURL)
		if err != nil {
			log.Fatalf("Error fetching authorization url %q: %v", authURL, err)
		}
		log.Printf("Fetched authorization: %s", auth.Identifier.Value)

		// let see dns
		chaldns, ok := auth.ChallengeMap[acme.ChallengeTypeDNS01]
		if !ok {
			log.Fatalf("Unable to find http challenge for auth %s", auth.Identifier.Value)
		}

		log.Println("host ->", "_acme-challenge."+auth.Identifier.Value+".")
		log.Println("chaldns authorization type ->", chaldns.Type)
		log.Println("chaldns dns value ->", acme.EncodeDNS01KeyAuthorization(chaldns.KeyAuthorization))

		// update the acme server that the challenge file is ready to be queried
		log.Printf("Updating challenge for authorization %s: %s", auth.Identifier.Value, chaldns.URL)
		chaldns, err = client.UpdateChallenge(account, chaldns)
		if err != nil {
			log.Fatalf("Error updating authorization %s challenge: %v", auth.Identifier.Value, err)
		}
		log.Printf("Challenge updated")

	}

	// all the challenges should now be completed

	// create a csr for the new certificate
	log.Printf("Generating certificate private key")
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("Error generating certificate key: %v", err)
	}
	// encode the new ec private key
	certKeyEnc, err := x509.MarshalECPrivateKey(certKey)
	if err != nil {
		log.Fatalf("Error encoding certificate key file: %v", err)
	}

	// write the key to the key file as a pem encoded key
	log.Printf("Writing key file: %s", location+domain+"/"+keyFile)
	if err := os.WriteFile(location+domain+"/"+keyFile, pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: certKeyEnc,
	}), 0644); err != nil {
		log.Fatalf("Error writing key file %q: %v", domain+"/"+keyFile, err)
	}

	// create the new csr template
	// log.Printf("Creating csr")
	tpl := &x509.CertificateRequest{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		PublicKeyAlgorithm: x509.ECDSA,
		PublicKey:          certKey.Public(),
		Subject:            pkix.Name{CommonName: domainList[0]},
		DNSNames:           domainList,
	}
	csrDer, err := x509.CreateCertificateRequest(rand.Reader, tpl, certKey)
	if err != nil {
		log.Fatalf("Error creating certificate request: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDer)
	if err != nil {
		log.Fatalf("Error parsing certificate request: %v", err)
	}

	// finalize the order with the acme server given a csr
	log.Printf("Finalising order: %s", order.URL)
	order, err = client.FinalizeOrder(account, order, csr)
	if err != nil {
		log.Fatalf("Error finalizing order: %v", err)
	}

	// fetch the certificate chain from the finalized order provided by the acme server
	log.Printf("Fetching certificate: %s", order.Certificate)
	certs, err := client.FetchCertificates(account, order.Certificate)
	if err != nil {
		log.Fatalf("Error fetching order certificates: %v", err)
	}

	// write the pem encoded certificate chain to file
	log.Printf("Saving certificate to: %s", domain+"/"+certFile)
	var pemData []string
	for _, c := range certs {
		pemData = append(pemData, strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: c.Raw,
		}))))
	}
	if err := os.WriteFile(location+domain+"/"+certFile, []byte(strings.Join(pemData, "\n")), 0644); err != nil {
		log.Fatalf("Error writing certificate file %q: %v", location+domain+"/"+certFile, err)
	}

	log.Printf("Done.")
}

func matchCertificate(domain string, renew int64) int {
	timeNow := time.Now()
	pubBytes, err := os.ReadFile(location + domain + "/" + certFile)
	if err != nil {
		log.Printf("There's no certificate with domain -> %s, errors -> %s \n", domain+"/"+certFile, err)
		return 2
	}
	pubBlock, _ := pem.Decode(pubBytes)
	if pubBlock == nil {
		fmt.Println("read cert error")
		return 2
	}

	cert, err := x509.ParseCertificate(pubBlock.Bytes)
	if err != nil {
		log.Printf("pubBytes -> %s, errors -> %s \n", string(pubBytes), err)
		return 2
	}
	expiresIn := int64(cert.NotAfter.Sub(timeNow).Hours())

	if expiresIn <= renew*24 {
		// log.Println("certificate will expire within 10 days")
		return 0
	}
	return -1
}

func loadAccount(client acme.Client) (acme.Account, error) {
	raw, err := os.ReadFile(location + accountFile)
	if err != nil {
		return acme.Account{}, fmt.Errorf("error reading account file %q: %v", accountFile, err)
	}
	var aaf acmeAccFile
	if err := json.Unmarshal(raw, &aaf); err != nil {
		return acme.Account{}, fmt.Errorf("error parsing account file %q: %v", accountFile, err)
	}

	block, _ := pem.Decode([]byte(aaf.PrivateKey))
	if block == nil {
		log.Fatal("failed to decode PEM block containing private key")
	}

	privKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	account, err := client.UpdateAccount(acme.Account{PrivateKey: privKey, URL: aaf.URL})
	if err != nil {
		return acme.Account{}, fmt.Errorf("error updating existing account: %v", err)
	}
	return account, nil
}

func createAccount(client acme.Client) (acme.Account, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return acme.Account{}, fmt.Errorf("error creating private key: %v", err)
	}

	eab := acme.ExternalAccountBinding{
		KeyIdentifier: os.Getenv("KID"),
		MacKey:        os.Getenv("HMAC"),
		Algorithm:     "HS256",
		HashFunc:      crypto.SHA256,
	}
	account, err := client.NewAccountOptions(privKey, acme.NewAcctOptAgreeTOS(), acme.NewAcctOptExternalAccountBinding(eab))
	if err != nil {
		return acme.Account{}, fmt.Errorf("error creating new account: %v", err)
	}
	prvkey, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		log.Fatalf("Error encoding certificate key file: %v", err)
	}
	prvPem := string(pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: prvkey,
	}))

	aaf := acmeAccFile{
		PrivateKey: prvPem,
		URL:        account.URL,
	}
	raw, err := json.Marshal(aaf)
	if err != nil {
		return acme.Account{}, fmt.Errorf("error parsing new account: %v", err)
	}
	if err := os.WriteFile(location+accountFile, raw, 0644); err != nil {
		return acme.Account{}, fmt.Errorf("error creating account file: %v", err)
	}
	return account, nil
}

type acmeAccFile struct {
	PrivateKey string `json:"privatekey"`
	URL        string `json:"url"`
}
