package discovery

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestNmapImportParsesHostsAndOpenServices(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scan.xml")
	xml := `<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx" version="1.25"/></port>
      <port protocol="tcp" portid="22"><state state="closed"/><service name="ssh"/></port>
      <port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port>
    </ports>
  </host>
</nmaprun>`
	if err := os.WriteFile(path, []byte(xml), 0o644); err != nil {
		t.Fatal(err)
	}
	d := New(NmapImport{Path: path})
	b, err := d.Run(context.Background(), Job{})
	if err != nil {
		t.Fatal(err)
	}
	hosts, services := 0, 0
	for _, o := range b.Components {
		switch o.Kind {
		case "host":
			hosts++
		case "service":
			services++
		}
	}
	if hosts != 1 {
		t.Fatalf("hosts = %d, want 1", hosts)
	}
	if services != 2 { // only the two open ports (closed 22 excluded)
		t.Fatalf("open services = %d, want 2", services)
	}
}
