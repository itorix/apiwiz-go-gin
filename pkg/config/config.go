package config

type Config struct {
	APIKey                  string
	WorkspaceID            string
	DetectAPI              string
	EnableTracing          bool
	TraceIDHeader          string
	SpanIDHeader           string
	ParentSpanIDHeader     string
	RequestTimestampHeader string
	ResponseTimestampHeader string
	GatewayTypeHeader      string
}