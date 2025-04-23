package config

type Config struct {
	APIKey                  string
	WorkspaceID             string
	DetectAPI               string
	EnableTracing           bool
	TraceIDHeader           string
	SpanIDHeader            string
	ParentSpanIDHeader      string
	RequestTimestampHeader  string
	ResponseTimestampHeader string
	GatewayTypeHeader       string
	DecryptData             bool
	AES256_KEY              string
	AES256_IV               string
	EncryptedFieldPath      string
}
