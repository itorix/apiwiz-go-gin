# APIWiz Gin Detect SDK

This SDK provides request/response monitoring and tracing capabilities for Fiber applications integrated with APIWiz.

## Installation

```bash
go get github.com/itorix/apiwiz-go-gin
```

## Configuration

Add the following configuration to your application:

```go
cfg := &config.Config{
    APIKey:      "your-api-key",
    IndexName:   "your-index-name"
    WorkspaceID: "your-workspace-id",
    DetectAPI:   "your-detect-api-url",
    EnableTracing: true,
    TraceIDHeader: "X-Trace-ID",
    SpanIDHeader:  "X-Span-ID",
    ParentSpanIDHeader: "X-ParentSpan-ID",
    RequestTimestampHeader: "request-timestamp",
    ResponseTimestampHeader: "response-timestamp",
    GatewayTypeHeader: "gateway-type",
    DecryptData: true,
    AES_KEY: "your-aes-key",
    AES_IV: "your-aes-iv",
    EncryptedFieldPath: "your-encrypted-data-path"
}
```

## Usage

```go
package main

import (
	"github.com/itorix/apiwiz-go-gin/pkg/config"
	"github.com/itorix/apiwiz-go-gin/pkg/middleware"
	"github.com/gin-gonic/gin"
)

func main() {
	router := gin.New()

    cfg := &config.Config{
        // your configuration here
    }

	detect := middleware.NewDetectMiddleware(cfg)
	router.Use(middleware.ApiwizDetectMiddleware(detect))

}
```

## Features

- Request/Response monitoring
- Distributed tracing
- Automatic server information collection
- Async compliance data sending
- Configurable headers

## License

MIT





