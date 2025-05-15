package restyfactory

import (
	"net/http"

	"github.com/go-resty/resty/v2"
	"github.com/itorix/apiwiz-go-gin/pkg/middleware"
)

func New() *resty.Client {
	client := resty.New()

	// Force all requests to use your custom header-injecting transport
	client.SetTransport(&middleware.HeaderInjectingTransport{
		Base: http.DefaultTransport,
	})

	return client
}
