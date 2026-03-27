// Command check connects to each HTTPS endpoint in a test-certs-site config,
// retrieves certificates and CRLs, and renders a self-contained HTML report.
package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"embed"
	"flag"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/letsencrypt/test-certs-site/config"
)

//go:embed report.html.tmpl
var reportTemplateFile embed.FS

func main() {
	outPath := flag.String("out", "", "output HTML file (default: stdout)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: check [flags] config1.json [config2.json ...]\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	cfgPaths := flag.Args()
	if len(cfgPaths) == 0 {
		cfgPaths = []string{"config.json"}
	}

	var sections []configSection
	for _, cfgPath := range cfgPaths {
		cfg, err := config.Load(cfgPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "loading config %s: %v\n", cfgPath, err)
			os.Exit(1)
		}

		addr := cfg.ListenAddr
		if addr == "" {
			addr = ":443"
		}

		sec := configSection{Name: cfgPath}
		for _, site := range cfg.Sites {
			sr := siteResult{
				IssuerCN: site.IssuerCN,
				KeyType:  site.KeyType,
				Profile:  site.Profile,
			}
			if site.Domains.Valid != "" {
				r := check(site.Domains.Valid, addr, site, "valid")
				sr.Valid = &r
			}
			if site.Domains.Expired != "" {
				r := check(site.Domains.Expired, addr, site, "expired")
				sr.Expired = &r
			}
			if site.Domains.Revoked != "" {
				r := check(site.Domains.Revoked, addr, site, "revoked")
				sr.Revoked = &r
			}
			sec.Sites = append(sec.Sites, sr)
		}
		sections = append(sections, sec)
	}

	html := renderHTML(sections)

	if *outPath != "" {
		err := os.WriteFile(*outPath, []byte(html), 0o644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "writing output: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "wrote %s\n", *outPath)
	} else {
		fmt.Print(html)
	}
}

type result struct {
	Domain     string
	Expected   string // "valid", "expired", "revoked"
	IssuerCN   string
	KeyType    string
	Profile    string
	ConnErr    string
	Chain      []certInfo
	CRLErr     string
	InCRL      bool
	NotBefore  time.Time
	NotAfter   time.Time
	IsExpired  bool
	Status     string // "valid", "expired", "revoked", "error"
	StatusDesc string
}

type certInfo struct {
	Subject    string
	Issuer     string
	NotBefore  time.Time
	NotAfter   time.Time
	Serial     string
	IsCA       bool
	KeyUsage   string
	SANs       []string
	CRLDistPts []string
}

func check(domain, listenAddr string, site config.Site, expect string) result {
	r := result{
		Domain:   domain,
		Expected: expect,
		IssuerCN: site.IssuerCN,
		KeyType:  site.KeyType,
		Profile:  site.Profile,
	}

	// Determine the dial address. The listenAddr may be ":port" or "host:port".
	_, port, _ := net.SplitHostPort(listenAddr)
	if port == "" {
		port = "443"
	}
	dialAddr := net.JoinHostPort(domain, port)

	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 10 * time.Second},
		"tcp",
		dialAddr,
		&tls.Config{
			ServerName:         domain,
			InsecureSkipVerify: true, //nolint:gosec // We need to inspect expired/revoked certs
		},
	)
	if err != nil {
		r.ConnErr = err.Error()
		r.Status = "error"
		r.StatusDesc = fmt.Sprintf("connection failed: %v", err)
		return r
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		r.ConnErr = "no certificates presented"
		r.Status = "error"
		r.StatusDesc = "no certificates presented"
		return r
	}

	leaf := certs[0]
	r.NotBefore = leaf.NotBefore
	r.NotAfter = leaf.NotAfter
	r.IsExpired = time.Now().After(leaf.NotAfter)

	for _, c := range certs {
		ci := certInfo{
			Subject:    c.Subject.CommonName,
			Issuer:     c.Issuer.CommonName,
			NotBefore:  c.NotBefore,
			NotAfter:   c.NotAfter,
			Serial:     c.SerialNumber.Text(16),
			IsCA:       c.IsCA,
			SANs:       c.DNSNames,
			CRLDistPts: c.CRLDistributionPoints,
			KeyUsage:   formatKeyUsage(c),
		}
		r.Chain = append(r.Chain, ci)
	}

	// Check CRL for the leaf certificate.
	if len(leaf.CRLDistributionPoints) > 0 {
		revoked, crlErr := checkCRL(leaf)
		if crlErr != nil {
			r.CRLErr = crlErr.Error()
		} else {
			r.InCRL = revoked
		}
	}

	// Determine status.
	switch {
	case r.ConnErr != "":
		r.Status = "error"
		r.StatusDesc = r.ConnErr
	case expect == "revoked" && r.InCRL:
		r.Status = "revoked"
		r.StatusDesc = "Certificate is revoked (found in CRL) — correct"
	case expect == "revoked" && !r.InCRL && r.CRLErr != "":
		r.Status = "error"
		r.StatusDesc = fmt.Sprintf("Expected revoked but CRL check failed: %s", r.CRLErr)
	case expect == "revoked" && !r.InCRL:
		r.Status = "error"
		r.StatusDesc = "Expected revoked but certificate NOT found in CRL"
	case expect == "expired" && r.IsExpired:
		r.Status = "expired"
		r.StatusDesc = "Certificate is expired — correct"
	case expect == "expired" && !r.IsExpired:
		r.Status = "error"
		r.StatusDesc = fmt.Sprintf("Expected expired but certificate is valid until %s", r.NotAfter.Format(time.RFC3339))
	case expect == "valid" && !r.IsExpired && !r.InCRL:
		r.Status = "valid"
		r.StatusDesc = "Certificate is valid — correct"
	case expect == "valid" && r.IsExpired:
		r.Status = "error"
		r.StatusDesc = "Expected valid but certificate is expired"
	case expect == "valid" && r.InCRL:
		r.Status = "error"
		r.StatusDesc = "Expected valid but certificate is revoked"
	default:
		r.Status = "error"
		r.StatusDesc = "Unexpected state"
	}

	return r
}

func checkCRL(cert *x509.Certificate) (bool, error) {
	client := &http.Client{Timeout: 10 * time.Second}

	for _, crlURL := range cert.CRLDistributionPoints {
		resp, err := client.Get(crlURL) //nolint:gosec // CRL URL comes from the certificate
		if err != nil {
			return false, fmt.Errorf("fetching CRL %s: %w", crlURL, err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return false, fmt.Errorf("reading CRL body: %w", err)
		}

		crl, err := x509.ParseRevocationList(body)
		if err != nil {
			return false, fmt.Errorf("parsing CRL from %s: %w", crlURL, err)
		}

		for _, entry := range crl.RevokedCertificateEntries {
			if entry.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				return true, nil
			}
		}
	}

	return false, nil
}

func formatKeyUsage(c *x509.Certificate) string {
	var usages []string
	if c.KeyUsage&x509.KeyUsageDigitalSignature != 0 {
		usages = append(usages, "Digital Signature")
	}
	if c.KeyUsage&x509.KeyUsageCertSign != 0 {
		usages = append(usages, "Certificate Sign")
	}
	if c.KeyUsage&x509.KeyUsageCRLSign != 0 {
		usages = append(usages, "CRL Sign")
	}
	if c.KeyUsage&x509.KeyUsageKeyEncipherment != 0 {
		usages = append(usages, "Key Encipherment")
	}
	for _, eku := range c.ExtKeyUsage {
		switch eku {
		case x509.ExtKeyUsageServerAuth:
			usages = append(usages, "Server Auth")
		case x509.ExtKeyUsageClientAuth:
			usages = append(usages, "Client Auth")
		}
	}
	return strings.Join(usages, ", ")
}

type configSection struct {
	Name  string
	Sites []siteResult
}

type siteResult struct {
	IssuerCN string
	KeyType  string
	Profile  string
	Valid    *result
	Expired  *result
	Revoked  *result
}

// statusCell is a template-friendly representation of one status column.
type statusCell struct {
	Result     *result
	Label      string
	ID         string
	Emoji      string
	BadgeClass string
}

// reportData is the top-level data passed to the HTML template.
type reportData struct {
	GeneratedAt string
	Sections    []configSection
	NValid      int
	NExpired    int
	NRevoked    int
	NErr        int
	Total       int
}

var reportTemplate = template.Must(
	template.New("report.html.tmpl").Funcs(template.FuncMap{
		"profileOrDash": func(s string) string {
			if s == "" {
				return "\u2014"
			}
			return s
		},
		"statusCells": func(secIdx, siteIdx int, s siteResult) []statusCell {
			var cells []statusCell
			for _, pair := range []struct {
				r     *result
				label string
			}{
				{s.Valid, "valid"},
				{s.Expired, "expired"},
				{s.Revoked, "revoked"},
			} {
				sc := statusCell{
					Result: pair.r,
					Label:  pair.label,
					ID:     fmt.Sprintf("p%d-%d-%s", secIdx, siteIdx, pair.label),
				}
				if pair.r != nil {
					sc.Emoji, sc.BadgeClass = statusBadge(pair.r.Status)
				}
				cells = append(cells, sc)
			}
			return cells
		},
		"chainLabel": func(j int, ci certInfo, chainLen int) string {
			if j == 0 {
				return "Leaf"
			}
			if ci.IsCA && j == chainLen-1 {
				return "Root / Top"
			}
			return fmt.Sprintf("Intermediate #%d", j)
		},
		"joinStrings": strings.Join,
	}).ParseFS(reportTemplateFile, "report.html.tmpl"),
)

func renderHTML(sections []configSection) string {
	var nValid, nExpired, nRevoked, nErr int
	for _, sec := range sections {
		for _, s := range sec.Sites {
			for _, r := range []*result{s.Valid, s.Expired, s.Revoked} {
				if r == nil {
					continue
				}
				switch r.Status {
				case "valid":
					nValid++
				case "expired":
					nExpired++
				case "revoked":
					nRevoked++
				case "error":
					nErr++
				}
			}
		}
	}

	data := reportData{
		GeneratedAt: time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
		Sections:    sections,
		NValid:      nValid,
		NExpired:    nExpired,
		NRevoked:    nRevoked,
		NErr:        nErr,
		Total:       nValid + nExpired + nRevoked + nErr,
	}

	var buf bytes.Buffer
	if err := reportTemplate.Execute(&buf, data); err != nil {
		panic(fmt.Sprintf("executing report template: %v", err))
	}
	return buf.String()
}

func statusBadge(status string) (emoji string, class string) {
	switch status {
	case "valid":
		return "✅", "badge-valid"
	case "expired":
		return "⏰", "badge-expired"
	case "revoked":
		return "🔪", "badge-revoked"
	default:
		return "❌", "badge-error"
	}
}
