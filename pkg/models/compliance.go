package models

type ComplianceCheckDTO struct {
	Request    Request  `json:"request"`
	Response   Response `json:"response"`
	ClientIP   string   `json:"clientIp,omitempty"`
	ClientHost string   `json:"clientHost,omitempty"`
	ServerIP   string   `json:"serverIp,omitempty"`
	ServerHost string   `json:"serverHost,omitempty"`
}

type Request struct {
	HeaderParams map[string]interface{} `json:"headerParams,omitempty"`
	QueryParams  map[string]interface{} `json:"queryParams,omitempty"`
	FormParams   map[string]interface{} `json:"formParams,omitempty"`
	PathParams   map[string]interface{} `json:"pathParams,omitempty"`
	Verb         string                 `json:"verb,omitempty"`
	Path         string                 `json:"path,omitempty"`
	Hostname     string                 `json:"hostname,omitempty"`
	RequestBody  string                 `json:"requestBody,omitempty"`
	Scheme       string                 `json:"scheme,omitempty"`
	Port         int                    `json:"port,omitempty"`
}

type Response struct {
	HeaderParams map[string]interface{} `json:"headerParams,omitempty"`
	ResponseBody string                 `json:"responseBody,omitempty"`
	StatusCode   string                 `json:"statusCode,omitempty"`
}
