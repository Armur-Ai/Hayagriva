package discovery

import (
	"context"
	"encoding/xml"
	"os"
	"time"

	contracts "github.com/Armur-Ai/armur-contracts"
)

// NmapImport is a Collector that imports an nmap XML file as discovery evidence:
// hosts, open ports and the services on them. Pure parsing, no network. Part of
// the P1 recon extraction from Pentest Swarm's tool ingestion.
type NmapImport struct {
	Path string // path to an `nmap -oX` XML file
}

func (NmapImport) Name() string { return "nmap-import" }

// nmapRun mirrors the subset of the nmap XML schema we consume.
type nmapRun struct {
	Hosts []struct {
		Addresses []struct {
			Addr string `xml:"addr,attr"`
			Type string `xml:"addrtype,attr"`
		} `xml:"address"`
		Ports struct {
			Ports []struct {
				Protocol string `xml:"protocol,attr"`
				PortID   string `xml:"portid,attr"`
				State    struct {
					State string `xml:"state,attr"`
				} `xml:"state"`
				Service struct {
					Name    string `xml:"name,attr"`
					Product string `xml:"product,attr"`
					Version string `xml:"version,attr"`
				} `xml:"service"`
			} `xml:"port"`
		} `xml:"ports"`
	} `xml:"host"`
}

func (n NmapImport) Collect(ctx context.Context, _ Job) ([]contracts.ComponentObservation, contracts.CollectorRun, error) {
	run := contracts.CollectorRun{Name: n.Name()}
	data, err := os.ReadFile(n.Path)
	if err != nil {
		run.Unavailable = "cannot read nmap file: " + err.Error()
		return nil, run, err
	}
	var doc nmapRun
	if err := xml.Unmarshal(data, &doc); err != nil {
		run.Unavailable = "parse nmap xml: " + err.Error()
		return nil, run, err
	}

	now := time.Now().UTC()
	var out []contracts.ComponentObservation
	for _, h := range doc.Hosts {
		if err := ctx.Err(); err != nil {
			return out, run, err
		}
		addr := primaryAddr(h.Addresses)
		if addr == "" {
			continue
		}
		out = append(out, contracts.ComponentObservation{
			Ref: "host:" + addr, Kind: "host", Value: addr,
			ObservedBy: n.Name(), ObservedAt: now, Trust: contracts.TrustObserved,
		})
		for _, p := range h.Ports.Ports {
			if p.State.State != "open" {
				continue // only open ports are surface
			}
			attrs := map[string]string{"protocol": p.Protocol, "port": p.PortID}
			if p.Service.Product != "" {
				attrs["product"] = p.Service.Product
			}
			if p.Service.Version != "" {
				attrs["version"] = p.Service.Version
			}
			svc := p.Service.Name
			if svc == "" {
				svc = "unknown"
			}
			out = append(out, contracts.ComponentObservation{
				Ref: "svc:" + addr + ":" + p.PortID, Kind: "service",
				Value: addr + ":" + p.PortID + "/" + svc, Attributes: attrs,
				ObservedBy: n.Name(), ObservedAt: now, Trust: contracts.TrustObserved,
			})
		}
	}
	run.Ran = true
	return out, run, nil
}

func primaryAddr(addrs []struct {
	Addr string `xml:"addr,attr"`
	Type string `xml:"addrtype,attr"`
}) string {
	// Prefer an IPv4 address; fall back to the first.
	for _, a := range addrs {
		if a.Type == "ipv4" {
			return a.Addr
		}
	}
	if len(addrs) > 0 {
		return addrs[0].Addr
	}
	return ""
}
