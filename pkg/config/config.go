package config

type Config struct {
	APIKey                  string
	IndexName               string
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
	AES_KEY                 string
	AES_IV                  string
	EncryptedFieldPath      string
}
