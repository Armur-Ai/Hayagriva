package discovery

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"time"

	contracts "github.com/Armur-Ai/armur-contracts"
)

// OpenAPIImport is a Collector that imports an OpenAPI v3 or Swagger v2 document
// (JSON) and expands its declared paths + operations into endpoint
// ComponentObservations. Pure parsing, no network. This turns an API spec an
// operator already has into discovery surface for the suite.
type OpenAPIImport struct {
	Path string // path to an openapi.json / swagger.json file
}

func (OpenAPIImport) Name() string { return "openapi-import" }

type openapiDoc struct {
	OpenAPI  string `json:"openapi"`  // v3
	Swagger  string `json:"swagger"`  // v2
	Host     string `json:"host"`     // v2
	BasePath string `json:"basePath"` // v2
	Servers  []struct {
		URL string `json:"url"`
	} `json:"servers"` // v3
	Paths map[string]map[string]json.RawMessage `json:"paths"`
}

var httpMethods = map[string]bool{
	"get": true, "post": true, "put": true, "delete": true,
	"patch": true, "head": true, "options": true, "trace": true,
}

func (o OpenAPIImport) Collect(ctx context.Context, _ Job) ([]contracts.ComponentObservation, contracts.CollectorRun, error) {
	run := contracts.CollectorRun{Name: o.Name()}
	data, err := os.ReadFile(o.Path)
	if err != nil {
		run.Unavailable = "cannot read spec: " + err.Error()
		return nil, run, err
	}
	var doc openapiDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		run.Unavailable = "parse openapi/swagger json: " + err.Error()
		return nil, run, err
	}

	base := specBase(doc)
	now := time.Now().UTC()
	var out []contracts.ComponentObservation
	for path, ops := range doc.Paths {
		if err := ctx.Err(); err != nil {
			return out, run, err
		}
		full := base + path
		for method := range ops {
			m := strings.ToLower(method)
			if !httpMethods[m] {
				continue // skip non-operation keys (parameters, $ref, ...)
			}
			out = append(out, contracts.ComponentObservation{
				Ref:        "openapi:" + strings.ToUpper(m) + ":" + full,
				Kind:       "endpoint",
				Value:      strings.ToUpper(m) + " " + full,
				Attributes: map[string]string{"source": "openapi", "method": strings.ToUpper(m)},
				ObservedBy: o.Name(), ObservedAt: now, Trust: contracts.TrustAsserted, // declared in a spec, not probed
			})
		}
	}
	run.Ran = true
	return out, run, nil
}

// specBase derives a base URL/prefix from either an OpenAPI v3 server or a
// Swagger v2 host+basePath. Returns "" when none is declared.
func specBase(d openapiDoc) string {
	if len(d.Servers) > 0 && d.Servers[0].URL != "" {
		return strings.TrimRight(d.Servers[0].URL, "/")
	}
	if d.Host != "" {
		return strings.TrimRight(d.Host+d.BasePath, "/")
	}
	return strings.TrimRight(d.BasePath, "/")
}
