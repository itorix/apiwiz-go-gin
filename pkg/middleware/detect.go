package middleware

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/itorix/apiwiz-go-gin/pkg/config"
	"github.com/itorix/apiwiz-go-gin/pkg/models"
)

var originalTransport http.RoundTripper

// Thread-local storage for request headers
var requestHeadersStore sync.Map // maps goroutine ID to http.Header

func init() {

	// Save the original default transport
	originalTransport = http.DefaultTransport

	// Replace with our custom transport
	http.DefaultTransport = &HeaderInjectingTransport{
		Base: originalTransport,
	}

}

// Custom transport that injects headers
type HeaderInjectingTransport struct {
	Base http.RoundTripper
}

// RoundTrip implements the http.RoundTripper interface
func (t *HeaderInjectingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Get the current goroutine ID
	gID := getGoroutineID()

	// Look up headers for this goroutine
	if headersVal, ok := requestHeadersStore.Load(gID); ok {
		if headers, ok := headersVal.(http.Header); ok {
			for name, values := range headers {

				for _, value := range values {
					if req.Header.Get(name) == "" {
						req.Header.Add(name, value)
					}
				}

			}
		}
	}

	return t.Base.RoundTrip(req)
}

// Set the current request headers for the current goroutine
func SetCurrentRequestHeaders(headers http.Header, detect *DetectMiddleware) {
	gID := getGoroutineID()
	headersCopy := make(http.Header)
	for k, v := range headers {
		if strings.EqualFold(k, detect.config.TraceIDHeader) || strings.EqualFold(k, detect.config.SpanIDHeader) {
			headersCopy[k] = v
		}
	}
	requestHeadersStore.Store(gID, headersCopy)
}

// Clear the current request headers
func ClearCurrentRequestHeaders() {
	gID := getGoroutineID()
	requestHeadersStore.Delete(gID)
}

// Function to get the current goroutine ID
func getGoroutineID() uint64 {
	b := make([]byte, 64)
	b = b[:runtime.Stack(b, false)]
	b = bytes.TrimPrefix(b, []byte("goroutine "))
	b = b[:bytes.IndexByte(b, ' ')]
	n, _ := strconv.ParseUint(string(b), 10, 64)
	return n
}

// Custom response writer to capture the response
type responseWriter struct {
	gin.ResponseWriter
	body *bytes.Buffer
}

func (w *responseWriter) Write(b []byte) (int, error) {
	w.body.Write(b)
	return w.ResponseWriter.Write(b)
}

// DetectRequest represents the request information to be processed by the detect handler
type DetectRequest struct {
	Method       string
	URL          string
	Headers      http.Header
	QueryParams  url.Values
	RequestBody  string
	ResponseBody string
	StatusCode   int
}

// Corrected middleware implementation

func ApiwizDetectMiddleware(detect *DetectMiddleware) gin.HandlerFunc {
	return func(c *gin.Context) {

		log.Printf("Captured the request")
		// Capture request body
		var requestBody []byte
		if c.Request.Body != nil {
			requestBody, _ = io.ReadAll(c.Request.Body)
			// Restore the request body for later use
			c.Request.Body = io.NopCloser(bytes.NewBuffer(requestBody))
		}

		// Create custom response writer to capture response
		customWriter := &responseWriter{
			ResponseWriter: c.Writer,
			body:           &bytes.Buffer{},
		}
		c.Writer = customWriter

		if detect.config.EnableTracing {
			traceID := c.GetHeader(detect.config.TraceIDHeader)
			spanID := c.GetHeader(detect.config.SpanIDHeader)
			var spanIDGenerated string
			spanIDGenerated = generateRandomHexString()
			if traceID == "" {
				traceID = spanIDGenerated
			}
			c.Request.Header.Set(detect.config.TraceIDHeader, traceID)
			c.Request.Header.Set(detect.config.SpanIDHeader, spanIDGenerated)
			c.Request.Header.Set(detect.config.ParentSpanIDHeader, spanID)
			c.Request.Header.Set(detect.config.RequestTimestampHeader, strconv.FormatInt(time.Now().UnixMilli(), 10))
		}

		SetCurrentRequestHeaders(c.Request.Header, detect)

		// Process the request through the chain
		c.Next()

		ClearCurrentRequestHeaders()

		ctxCopy := c.Copy()

		go func() {
			// Now we have access to both request and response data
			detectReq := &DetectRequest{
				Method:       c.Request.Method,
				URL:          c.Request.URL.String(),
				Headers:      c.Request.Header,
				QueryParams:  c.Request.URL.Query(),
				RequestBody:  string(requestBody),
				ResponseBody: customWriter.body.String(), // Response body is now available
				StatusCode:   c.Writer.Status(),          // Final status code is available
			}

			// Store the detect request in the context for the Handle function
			ctxCopy.Set("detectRequest", detectReq)
			detect.Handle()(ctxCopy)
			// Call Handle after we have all the response data
			// detect.HandleDetectRequest(detectReq, c.Request, c.Request.Host, c.Request.Proto, c.ClientIP())
		}()
	}
}

type DetectMiddleware struct {
	config *config.Config
	client *http.Client
}

func NewDetectMiddleware(cfg *config.Config) *DetectMiddleware {
	return &DetectMiddleware{
		config: cfg,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func generateRandomHexString() string {
	b := make([]byte, 8)
	_, err := rand.Read(b)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

type bodyLogWriter struct {
	gin.ResponseWriter
	body *bytes.Buffer
}

func (w bodyLogWriter) Write(b []byte) (int, error) {
	w.body.Write(b)
	return w.ResponseWriter.Write(b)
}

func (m *DetectMiddleware) Handle() gin.HandlerFunc {
	return func(c *gin.Context) {

		// Get the detect request from the context
		detectReqInterface, exists := c.Get("detectRequest")
		if !exists {
			return
		}

		detectReq := detectReqInterface.(*DetectRequest)

		// Prepare request data using the captured information
		data := &RequestData{
			Method:       detectReq.Method,
			Path:         c.Request.URL.Path,
			Body:         detectReq.RequestBody,
			Hostname:     c.Request.Host,
			Protocol:     c.Request.Proto,
			Request:      c.Request,
			ResponseBody: detectReq.ResponseBody, // Use the captured response body
			StatusCode:   detectReq.StatusCode,
			Host:         c.Request.Host,
			IP:           c.ClientIP(),
			LocalIP:      c.Request.Host,
		}

		// Handle compliance check asynchronously
		go func() {
			log.Printf("Preparing Compliance Body")
			m.handleComplianceCheck(data, []byte(detectReq.RequestBody))
		}()
	}
}

// func (m *DetectMiddleware) HandleDetectRequest(
// 	detectReq *DetectRequest,
// 	request *http.Request,
// 	host string,
// 	protocol string,
// 	ip string,
// ) {
// 	data := &RequestData{
// 		Method:       detectReq.Method,
// 		Path:         request.URL.Path,
// 		Body:         detectReq.RequestBody,
// 		Hostname:     host,
// 		Protocol:     protocol,
// 		Request:      request,
// 		ResponseBody: detectReq.ResponseBody,
// 		StatusCode:   detectReq.StatusCode,
// 		Host:         host,
// 		IP:           ip,
// 		LocalIP:      host,
// 	}
// 	go func() {
// 		log.Printf("Preparing Compliance Body")
// 		m.handleComplianceCheck(data, []byte(detectReq.RequestBody))
// 	}()
// }

type RequestData struct {
	Method       string
	Path         string
	Body         string
	Hostname     string
	Protocol     string
	Request      *http.Request
	ResponseBody string
	StatusCode   int
	Host         string
	IP           string
	LocalIP      string
}

func getPort(host, scheme string) int {
	if host == "" {
		return 80
	}

	if strings.Contains(host, ":") {
		portStr := strings.Split(host, ":")[1]
		if port, err := strconv.Atoi(portStr); err == nil {
			return port
		}
	}

	if strings.ToLower(scheme) == "https" {
		return 443
	}
	return 80
}

func (m *DetectMiddleware) handleComplianceCheck(data *RequestData, originalBody []byte) {
	checkDTO := m.buildComplianceDTO(data, originalBody)
	if checkDTO == nil {
		log.Println("checkDTO is nil, skipping compliance check")
		return
	}
	m.sendComplianceCheck(checkDTO)
}

func (m *DetectMiddleware) buildComplianceDTO(data *RequestData, originalBody []byte) *models.ComplianceCheckDTO {
	port := getPort(data.Host, data.Protocol)

	checkDTO := &models.ComplianceCheckDTO{
		Request: models.Request{
			HeaderParams: make(map[string]interface{}),
			QueryParams:  make(map[string]interface{}),
			Verb:         data.Method,
			Path:         data.Path,
			Hostname:     data.Hostname,
			RequestBody:  string(originalBody),
			Scheme:       strings.ToLower(strings.Split(data.Protocol, "/")[0]),
			Port:         port,
		},
		Response: models.Response{
			HeaderParams: make(map[string]interface{}),
			ResponseBody: data.ResponseBody,
			StatusCode:   fmt.Sprintf("%d", data.StatusCode),
		},
		ClientIP: data.IP,
		ServerIP: data.LocalIP,
	}

	// Add request headers
	for key, values := range data.Request.Header {
		checkDTO.Request.HeaderParams[strings.ToLower(key)] = values[0]
	}

	// Add tracing headers if enabled
	if m.config.EnableTracing {
		if m.config.ResponseTimestampHeader != "" {
			checkDTO.Request.HeaderParams[m.config.ResponseTimestampHeader] = time.Now().UnixMilli()
		}
		if m.config.GatewayTypeHeader != "" {
			checkDTO.Request.HeaderParams[m.config.GatewayTypeHeader] = "MICROSERVICES"
		}
	}
	refererString := ""
	referer := checkDTO.Request.HeaderParams["referer"]
	if referer != nil {
		refererString = referer.(string)
	}

	hostString := ""
	host := checkDTO.Request.HeaderParams["host"]
	if host != nil {
		hostString = host.(string)
	}

	checkDTO.ClientIP = refererString
	checkDTO.ServerHost = hostString
	return checkDTO
}

func (m *DetectMiddleware) sendComplianceCheck(checkDTO *models.ComplianceCheckDTO) {
	log.Printf("Sending Compliance Data")
	defer func() {
		if r := recover(); r != nil {
		}
	}()

	if m.config.DecryptData {
		if checkDTO.Request.RequestBody != "" {
			if m.config.EncryptedFieldPath != "" {
				checkDTO.Request.RequestBody = m.decryptJSONField(
					checkDTO.Request.RequestBody,
					m.config.EncryptedFieldPath,
					m.config.AES_KEY,
					m.config.AES_IV,
				)
			} else {
				plainText, err := GetAESDecrypted(checkDTO.Request.RequestBody, m.config.AES_KEY, m.config.AES_IV)
				if err == nil {
					checkDTO.Request.RequestBody = plainText
				}
			}
		}

		if checkDTO.Response.ResponseBody != "" {
			if m.config.EncryptedFieldPath != "" {
				checkDTO.Response.ResponseBody = m.decryptJSONField(
					checkDTO.Response.ResponseBody,
					m.config.EncryptedFieldPath,
					m.config.AES_KEY,
					m.config.AES_IV,
				)
			} else {
				plainText, err := GetAESDecrypted(checkDTO.Response.ResponseBody, m.config.AES_KEY, m.config.AES_IV)
				if err == nil {
					checkDTO.Response.ResponseBody = plainText
				}
			}
		}
	}

	jsonData, err := json.Marshal(checkDTO)
	if err != nil {
		log.Printf("JSON Initialization error: %v", err)
		return
	}

	req, err := http.NewRequest("POST", m.config.DetectAPI, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("Request Initialization error: %v", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-client-secret", m.config.APIKey)
	req.Header.Set("x-client-id", m.config.WorkspaceID)

	resp, err := m.client.Do(req)
	if err != nil {
		log.Printf("Compliance Request failed: %v", err)
		return
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Failed to read response body: %v", err)
		return
	}
	log.Printf("Compliance response status: %s", resp.Status)
	log.Printf("Compliance response body: %s", string(bodyBytes))

}

func GetAESDecrypted(encrypted string, transformationKey, initializationVectorString string) (string, error) {

	ciphertext, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", err
	}

	transformationKeyBytes := getKeyBytes(transformationKey)
	block, err := aes.NewCipher(transformationKeyBytes)
	if err != nil {
		return "", err
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return "", fmt.Errorf("ciphertext is not a multiple of the block size")
	}

	initializationVectorBytes := getKeyBytes(initializationVectorString)
	mode := cipher.NewCBCDecrypter(block, initializationVectorBytes)
	mode.CryptBlocks(ciphertext, ciphertext)

	plaintext := PKCS5UnPadding(ciphertext)

	return string(plaintext), nil
}

func PKCS5UnPadding(src []byte) []byte {
	length := len(src)
	unpadding := int(src[length-1])

	return src[:(length - unpadding)]
}

func getKeyBytes(transformationKey string) []byte {
	// Check if the transformation key is a hex string
	hexMatch, _ := regexp.MatchString("^[0-9a-fA-F]+$", transformationKey)

	var keyBytes []byte
	if hexMatch {
		// If it's a hex string, use it directly as UTF-8 bytes
		keyBytes = []byte(transformationKey)
	} else {
		// If not a hex string, try to decode it as Base64
		var err error
		keyBytes, err = base64.StdEncoding.DecodeString(transformationKey)
		if err != nil {
			return []byte(transformationKey)
		}
	}

	return keyBytes
}

func (m *DetectMiddleware) decryptJSONField(jsonStr, jsonPath, keyBase64, ivBase64 string) string {
	var jsonData map[string]interface{}
	err := json.Unmarshal([]byte(jsonStr), &jsonData)
	if err != nil {
		return jsonStr
	}

	if !strings.HasPrefix(jsonPath, "$.") {
		return jsonStr
	}

	path := strings.TrimPrefix(jsonPath, "$.")

	pathParts := strings.Split(path, ".")

	var currentMap interface{} = jsonData
	var parent map[string]interface{}
	var lastKey string

	for i, part := range pathParts {
		if i == len(pathParts)-1 {
			lastKey = part
			if parentMap, ok := currentMap.(map[string]interface{}); ok {
				parent = parentMap
			} else {
				return jsonStr
			}
			continue
		}

		if m, ok := currentMap.(map[string]interface{}); ok {
			if val, exists := m[part]; exists {
				currentMap = val
			} else {
				return jsonStr
			}
		} else {
			return jsonStr
		}
	}

	if parent != nil && lastKey != "" {
		if encryptedValue, ok := parent[lastKey].(string); ok {
			decryptedValue, err := GetAESDecrypted(encryptedValue, keyBase64, ivBase64)
			if err != nil {
				return jsonStr
			}
			return string(decryptedValue)
		}
	}

	return jsonStr
}
