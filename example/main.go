package main

import (
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/itorix/apiwiz-go-gin/pkg/config"
	"github.com/itorix/apiwiz-go-gin/pkg/middleware"
)

func main() {
	// Initialize the Gin router
	router := gin.New()
	router.Use(gin.Logger())
	router.Use(gin.Recovery())

	// Configure APIWiz Detect with logging
	cfg := &config.Config{
		APIKey:                  "XeX0u28Ya1a3CBm5tihMQFteeA6fZTy8avUIsJ0WnNOaEAM90Hcv9G2xo5z5hI4WMyHffxTAbP2LcXK4u6n5Pw==",
		WorkspaceID:             "stage-data",
		DetectAPI:               "https://dev-api.apiwiz.io/v1/apiwiz-runtime-agent/compliance/detect",
		EnableTracing:           true,
		TraceIDHeader:           "traceid",
		SpanIDHeader:            "spanid",
		ParentSpanIDHeader:      "parentspanid",
		RequestTimestampHeader:  "request-timestamp",
		ResponseTimestampHeader: "response-timestamp",
		GatewayTypeHeader:       "gateway-type",
	}

	// Initialize Detect Middleware
	detect := middleware.NewDetectMiddleware(cfg)
	if detect == nil {
		log.Fatal("Failed to initialize DetectMiddleware")
	}

	// Use the corrected middleware
	router.Use(middleware.ApiwizDetectMiddleware(detect))

	router.GET("/1", func(c *gin.Context) {

		req, err := http.NewRequest("GET", "http://localhost:3000/2", nil)
		if err != nil {
			c.String(http.StatusInternalServerError, "Error creating request to /2")
			return
		}

		for name, values := range c.Request.Header {
			for _, value := range values {
				req.Header.Add(strings.ToLower(name), value)
			}
		}

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			c.String(http.StatusInternalServerError, "Error calling /2")
			return
		}
		defer resp.Body.Close()

		req1, err1 := http.NewRequest("GET", "http://localhost:3000/3", nil)
		if err1 != nil {
			c.String(http.StatusInternalServerError, "Error creating request to /3")
			return
		}

		for name, values := range c.Request.Header {
			for _, value := range values {
				req1.Header.Add(strings.ToLower(name), value)
			}
		}

		client1 := &http.Client{}
		resp1, err1 := client1.Do(req1)
		if err1 != nil {
			c.String(http.StatusInternalServerError, "Error calling /3")
			return
		}
		defer resp1.Body.Close()
		c.String(http.StatusOK, "Endpoint 1")
	})

	router.GET("/2", func(c *gin.Context) {

		req, err := http.NewRequest("GET", "http://localhost:3000/3", nil)
		if err != nil {
			c.String(http.StatusInternalServerError, "Error creating request to /3")
			return
		}

		for name, values := range c.Request.Header {
			for _, value := range values {
				req.Header.Add(strings.ToLower(name), value)
			}
		}

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			c.String(http.StatusInternalServerError, "Error calling /2")
			return
		}
		defer resp.Body.Close()

		c.String(http.StatusOK, "Endpoint 2")
	})

	router.GET("/3", func(c *gin.Context) {

		req, err := http.NewRequest("GET", "http://localhost:3000/4", nil)
		if err != nil {
			c.String(http.StatusInternalServerError, "Error creating request to /4")
			return
		}

		for name, values := range c.Request.Header {
			for _, value := range values {
				req.Header.Add(strings.ToLower(name), value)
			}
		}

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			c.String(http.StatusInternalServerError, "Error calling /2")
			return
		}
		defer resp.Body.Close()

		c.String(http.StatusOK, "Endpoint 3")
	})

	router.GET("/4", func(c *gin.Context) {
		c.String(http.StatusOK, "Endpoint 4")
	})

	router.GET("/5", func(c *gin.Context) {

		req, err := http.NewRequest("GET", "http://localhost:3001/1", nil)
		if err != nil {
			c.String(http.StatusInternalServerError, "Error creating request to /1")
			return
		}

		for name, values := range c.Request.Header {
			for _, value := range values {
				req.Header.Add(strings.ToLower(name), value)
			}
		}

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			c.String(http.StatusInternalServerError, "Error calling /1")
			return
		}
		defer resp.Body.Close()

		c.String(http.StatusOK, "Endpoint 5")
	})

	// Add a health check endpoint
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "healthy",
			"time":   time.Now().Format(time.RFC3339),
		})
	})

	// Start the server
	if err := router.Run(":3000"); err != nil {
		log.Fatalf("Failed to start server: %v\n", err)
	}
}
