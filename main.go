package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/joho/godotenv"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"
)

type JwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

type ServiceAccount struct {
	ClientEmail string `json:"client_email"`
	PrivateKey  string `json:"private_key"`
	TokenUri    string `json:"token_uri"`
}

type GoogleAccessToken struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

type ClaimSet struct {
	Iss   string `json:"iss"`
	Scope string `json:"scope"`
	Aud   string `json:"aud"`
	Exp   int64  `json:"exp"`
	Iat   int64  `json:"iat"`
}

type VoidedPurchaseResponse struct {
	VoidedPurchases []VoidedPurchase `json:"voidedPurchases"`
}

type Purchase struct {
	PurchaseTimeMillis   string `json:"purchaseTimeMillis"`
	PurchaseState        int    `json:"purchaseState"`
	ConsumptionState     int    `json:"consumptionState"`
	DeveloperPayload     string `json:"developerPayload"`
	OrderId              string `json:"orderId"`
	PurchaseType         int    `json:"purchaseType"`
	AcknowledgementState int    `json:"acknowledgementState"`
	Kind                 string `json:"kind"`
	RegionCode           string `json:"regionCode"`
}

type VoidedPurchase struct {
	PurchaseToken      string `json:"purchaseToken"`
	PurchaseTimeMillis string `json:"purchaseTimeMillis"`
	VoidedTimeMillis   string `json:"voidedTimeMillis"`
	OrderId            string `json:"orderId"`
	VoidedSource       int    `json:"voidedSource"`
	VoidedReason       int    `json:"voidedReason"`
	Kind               string `json:"kind"`
}

func getReceiptByPurchaseToken(packageName, productId, purchaseToken string) *Purchase {

	credPath := os.Getenv("VOIDCHECKER_SERVICE_ACCOUNT_CRED_PATH")

	cachedAccessToken := getCachedAccessToken(credPath)

	getUrl := fmt.Sprintf("https://www.googleapis.com/androidpublisher/v3/applications/%v/purchases/products/%v/tokens/%v?access_token=%v", packageName, productId, purchaseToken, cachedAccessToken)

	log.Println("GET URL: " + getUrl)

	resp, err := http.Get(getUrl)

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Println(err)
		}
	}(resp.Body)

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	str := string(respBody)
	println("==================================")
	println(str)
	println("==================================")

	var purchase Purchase
	err = json.Unmarshal(respBody, &purchase)
	if err != nil {
		log.Println(err)
		return nil
	}

	return &purchase
}

func CheckGoogleForVoidedReceipts() {
	packageName := os.Getenv("VOIDCHECKER_ANDROID_PACKAGE_NAME")
	credPath := os.Getenv("VOIDCHECKER_SERVICE_ACCOUNT_CRED_PATH")

	cachedAccessToken := getCachedAccessToken(credPath)

	log.Println("Cached Access Token: " + cachedAccessToken)

	voidedGetUrl := fmt.Sprintf("https://www.googleapis.com/androidpublisher/v3/applications/%s/purchases/voidedpurchases?access_token=%s", packageName, cachedAccessToken)

	resp, err := http.Get(voidedGetUrl)

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Println(err)
		}
	}(resp.Body)

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	str := string(respBody)
	println(str)

	var voidedPurchaseResponse VoidedPurchaseResponse
	err = json.Unmarshal(respBody, &voidedPurchaseResponse)
	if err != nil {
		panic(err)
	}
}

var cachedAccessToken string
var lastAccessTokenUpdateTime = time.UnixMilli(0)

func getCachedAccessToken(credPath string) string {
	now := time.Now().UTC()

	tokenAge := now.Sub(lastAccessTokenUpdateTime)

	if tokenAge >= 30*time.Minute {
		cachedAccessToken = ""
	}

	if len(cachedAccessToken) == 0 {
		newAccessToken, err := getNewGoogleAccessToken(credPath)
		if err != nil {
			panic(err)
		}
		cachedAccessToken = newAccessToken.AccessToken
		lastAccessTokenUpdateTime = now
	}

	return cachedAccessToken
}

func getNewGoogleAccessToken(credPath string) (GoogleAccessToken, error) {
	headerBytes, err := json.Marshal(JwtHeader{Alg: "RS256", Typ: "JWT"})
	if err != nil {
		panic(err)
	}

	headerEncoded := base64.RawURLEncoding.EncodeToString(headerBytes)

	credStr, err := os.ReadFile(credPath)
	if err != nil {
		panic(err)
	}

	var serviceAccount ServiceAccount
	err = json.Unmarshal(credStr, &serviceAccount)
	if err != nil {
		panic(err)
	}

	log.Println(headerEncoded)
	log.Println(serviceAccount.ClientEmail)

	now := time.Now()

	const scope = "https://www.googleapis.com/auth/androidpublisher"

	claimSet := ClaimSet{
		Aud:   serviceAccount.TokenUri,
		Iss:   serviceAccount.ClientEmail,
		Iat:   now.Unix(),
		Exp:   now.Unix() + int64(time.Hour.Seconds()),
		Scope: scope,
	}

	claimSetBytes, err := json.Marshal(claimSet)
	if err != nil {
		panic(err)
	}

	log.Println(string(claimSetBytes))

	claimSetEncoded := base64.RawURLEncoding.EncodeToString(claimSetBytes)
	log.Println(claimSetEncoded)

	baseStrForSigEncoded := headerEncoded + "." + claimSetEncoded
	log.Println(baseStrForSigEncoded)

	h := sha256.New()
	h.Write([]byte(baseStrForSigEncoded))
	d := h.Sum(nil)

	block, _ := pem.Decode([]byte(serviceAccount.PrivateKey))
	parseResult, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}

	key := parseResult.(*rsa.PrivateKey)

	signatureBytes, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, d)
	if err != nil {
		panic(err)
	}

	signatureEncoded := base64.RawURLEncoding.EncodeToString(signatureBytes)
	log.Println(signatureEncoded)

	jwt := baseStrForSigEncoded + "." + signatureEncoded
	log.Println(jwt)

	const grantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"

	resp, err := http.PostForm(serviceAccount.TokenUri, url.Values{"grant_type": {grantType}, "assertion": {jwt}})
	if err != nil {
		panic(err)
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Println(err)
		}
	}(resp.Body)

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	str := string(respBody)
	println(str)

	var googleAccessToken GoogleAccessToken
	err = json.Unmarshal(respBody, &googleAccessToken)
	if err != nil {
		panic(err)
	}
	return googleAccessToken, err
}

func main() {
	goDotErr := godotenv.Load()
	if goDotErr != nil {
		log.Println("Error loading .env file")
	}

	CheckGoogleForVoidedReceipts()

	getReceiptByPurchaseToken(
		os.Getenv("VOIDCHECKER_ANDROID_PACKAGE_NAME"),
		os.Getenv("VOIDCHECKER_ANDROID_TEST_PRODUCT_ID"),
		os.Getenv("VOIDCHECKER_ANDROID_TEST_PURCHASE_TOKEN"),
	)

	http.HandleFunc("/verify", verifyHandler)

	listenAddr := ":60350"
	log.Println("LISTEN started on " + listenAddr)
	_ = http.ListenAndServe(listenAddr, nil)
}

func verifyHandler(writer http.ResponseWriter, request *http.Request) {
	packageName := ""
	productId := ""
	transactionId := ""

	for key := range request.Header {
		value := request.Header[key]
		log.Println(key, value)

		if key == "Package-Name" {
			packageName = value[0]
		} else if key == "Product-Id" {
			productId = value[0]
		} else if key == "Transaction-Id" {
			transactionId = value[0]
		}
	}

	receipt := getReceiptByPurchaseToken(packageName, productId, transactionId)
	if receipt == nil {
		writer.WriteHeader(http.StatusBadRequest)
		_, _ = writer.Write([]byte("FAILED"))
	} else {
		writer.Header().Set("Order-Id", receipt.OrderId)
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("OK"))
	}
}