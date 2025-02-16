package middleware

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"github.dev/itorix/apiwiz-go-gin/pkg/config"
	"github.dev/itorix/apiwiz-go-gin/pkg/models"
)

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

		// Process the request through the chain
		c.Next()

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
		c.Set("detectRequest", detectReq)

		// Call Handle after we have all the response data
		detect.Handle()(c)
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
			m.handleComplianceCheck(data, []byte(detectReq.RequestBody))
		}()
	}
}

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
	jsonData, err := json.Marshal(checkDTO)
	if err != nil {
		return
	}

	req, err := http.NewRequest("POST", m.config.DetectAPI, bytes.NewBuffer(jsonData))
	if err != nil {
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-client-secret", m.config.APIKey)
	req.Header.Set("x-client-id", m.config.WorkspaceID)

	resp, err := m.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

}
