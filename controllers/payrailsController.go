package controllers

import (
	"bytes"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type Config struct {
	ClientID        string
	APIKey          string
	BaseURL         string
	CertB64         string
	KeyB64          string
	StaticClientKey string
}

func LoadConfig() *Config {
	return &Config{
		ClientID:        os.Getenv("PAYRAILS_CLIENT_ID"),
		APIKey:          os.Getenv("PAYRAILS_API_KEY"),
		BaseURL:         os.Getenv("PAYRAILS_BASE_URL"),
		CertB64:         os.Getenv("MTLS_CLIENT_CERT"),
		KeyB64:          os.Getenv("MTLS_CLIENT_KEY"),
		StaticClientKey: os.Getenv("CLIENT_KEY"),
	}
}

var (
	cachedToken string
	tokenExpiry time.Time
	tokenMutex  sync.Mutex
)

// One HTTP client for the process, so connections to Payrails (and their mTLS handshakes) are reused.
var (
	clientOnce   sync.Once
	sharedClient *http.Client
	clientErr    error
)

const requestTimeout = 15 * time.Second

func payrailsClient(cfg *Config) (*http.Client, error) {
	clientOnce.Do(func() {
		sharedClient, clientErr = createMTLSClientFromBase64(cfg.CertB64, cfg.KeyB64)
	})
	return sharedClient, clientErr
}

func getBearerToken(cfg *Config, client *http.Client) (string, error) {
	if cfg.ClientID == "" || cfg.APIKey == "" || cfg.BaseURL == "" {
		return "", fmt.Errorf("clientId, apiKey, or baseUrl missing")
	}

	tokenMutex.Lock()
	defer tokenMutex.Unlock()

	if cachedToken != "" && time.Now().Before(tokenExpiry) {
		return cachedToken, nil
	}

	url := fmt.Sprintf("%s/auth/token/%s", cfg.BaseURL, cfg.ClientID)

	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("x-api-key", cfg.APIKey)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read token response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to fetch token: %s", string(body))
	}

	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return "", fmt.Errorf("invalid JSON in token response: %v", err)
	}

	token, ok := data["access_token"].(string)
	if !ok || token == "" {
		return "", fmt.Errorf("access_token missing in response")
	}

	cachedToken = token
	tokenExpiry = time.Now().Add(9 * time.Minute)
	return cachedToken, nil
}

func createMTLSClientFromBase64(certB64, keyB64 string) (*http.Client, error) {
	if certB64 == "" || keyB64 == "" {
		return &http.Client{Timeout: requestTimeout}, nil
	}

	certPEM, err := base64.StdEncoding.DecodeString(certB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode certificate: %v", err)
	}

	keyPEM, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode key: %v", err)
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to load X509 key pair: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	return &http.Client{
		Timeout: requestTimeout,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}, nil
}

func InitSDK(c *gin.Context) {
	cfg := LoadConfig()

	clientKey := c.GetHeader("x-client-key")
	if cfg.StaticClientKey == "" || subtle.ConstantTimeCompare([]byte(clientKey), []byte(cfg.StaticClientKey)) != 1 {
		c.JSON(401, gin.H{"error": "missing or invalid client key"})
		return
	}

	client, err := payrailsClient(cfg)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	token, err := getBearerToken(cfg, client)
	if err != nil {
		c.JSON(401, gin.H{"error": err.Error()})
		return
	}

	idempotencyKey := uuid.NewString()
	url := fmt.Sprintf("%s/merchant/client/init", cfg.BaseURL)

	var payload map[string]interface{}
	if err := c.ShouldBindJSON(&payload); err != nil || len(payload) == 0 {
		payload = map[string]interface{}{
			"type":             "dropIn",
			"workflowCode":     "payment-acceptance",
			"merchantReference": uuid.NewString(),
			"holderReference":   uuid.NewString(),
			"amount": map[string]string{
				"value":    "100",
				"currency": "EUR",
			},
		}
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonPayload))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-idempotency-key", idempotencyKey)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		c.JSON(502, gin.H{"error": err.Error()})
		return
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		c.JSON(502, gin.H{"error": err.Error()})
		return
	}
	var respData map[string]interface{}
	_ = json.Unmarshal(respBody, &respData)

	// Payrails' own errors are passed on as errors, with its status and body.
	if resp.StatusCode >= 400 {
		c.JSON(resp.StatusCode, gin.H{
			"status": "error",
			"data":   respData,
		})
		return
	}

	c.JSON(resp.StatusCode, gin.H{
		"status": "success",
		"data":   respData,
	})
}