// Command check connects to each HTTPS endpoint in a test-certs-site config,
// retrieves certificates and CRLs, and renders a self-contained HTML report.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/letsencrypt/test-certs-site/config"
)

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

func escapeHTML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	return s
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

func renderHTML(sections []configSection) string {
	var b strings.Builder

	b.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Certificate Check Report</title>
<style>
  *, *::before, *::after { box-sizing: border-box; }
  :root {
    --bg: #fafafa;
    --surface: #fff;
    --border: #e0e0e0;
    --text: #1a1a1a;
    --muted: #666;
    --green: #16a34a;
    --green-bg: #dcfce7;
    --red: #dc2626;
    --red-bg: #fee2e2;
    --amber: #d97706;
    --amber-bg: #fef3c7;
    --radius: 8px;
  }
  body {
    font-family: system-ui, -apple-system, sans-serif;
    background: var(--bg);
    color: var(--text);
    margin: 0;
    padding: 2rem;
    line-height: 1.5;
  }
  h1 { font-size: 1.5rem; font-weight: 600; margin: 0 0 0.25rem; }
  h2 { font-size: 1.1rem; font-weight: 600; margin: 1.5rem 0 0.5rem; }
  .subtitle { color: var(--muted); font-size: 0.875rem; margin-bottom: 1.5rem; }
  table {
    width: 100%;
    max-width: 56rem;
    table-layout: fixed;
    border-collapse: separate;
    border-spacing: 0;
    background: var(--surface);
    border-radius: var(--radius);
    box-shadow: 0 1px 3px rgba(0,0,0,0.08);
    margin-bottom: 1rem;
  }
  th:first-child { border-top-left-radius: var(--radius); }
  th:last-child  { border-top-right-radius: var(--radius); }
  tr:last-child td:first-child { border-bottom-left-radius: var(--radius); }
  tr:last-child td:last-child  { border-bottom-right-radius: var(--radius); }
  th, td {
    text-align: left;
    padding: 0.5rem 0.75rem;
    border-bottom: 1px solid var(--border);
    font-size: 0.85rem;
  }
  th {
    background: #f5f5f5;
    font-weight: 600;
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 0.03em;
    color: var(--muted);
  }
  tr:last-child td { border-bottom: none; }
  td.status-cell { position: relative; text-align: center; }
  .badge {
    display: inline-flex;
    align-items: center;
    gap: 0.3em;
    padding: 0.15em 0.5em;
    border-radius: 999px;
    font-size: 0.75rem;
    font-weight: 600;
    white-space: nowrap;
    cursor: pointer;
    user-select: none;
  }
  .badge:hover { filter: brightness(0.95); }
  .badge-valid   { background: var(--green-bg); color: var(--green); }
  .badge-expired { background: var(--amber-bg); color: var(--amber); }
  .badge-revoked { background: var(--red-bg);   color: var(--red); }
  .badge-error   { background: var(--red-bg);   color: var(--red); }
  .badge-none    { background: #f3f4f6; color: var(--muted); cursor: default; }
  .meta { color: var(--muted); font-size: 0.8rem; }
  .mono { font-family: ui-monospace, monospace; font-size: 0.8rem; }
  /* Popover */
  details.popover { display: inline; }
  details.popover summary { list-style: none; display: inline; }
  details.popover summary::-webkit-details-marker { display: none; }
  details.popover[open] .pop { display: block; }
  .pop {
    display: none;
    position: absolute;
    z-index: 10;
    top: 100%;
    left: 50%;
    transform: translateX(-50%);
    width: 440px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    box-shadow: 0 4px 16px rgba(0,0,0,0.12);
    padding: 0.75rem;
    font-size: 0.78rem;
    line-height: 1.5;
    text-align: left;
    cursor: default;
  }
  .pop h4 { margin: 0 0 0.4rem; font-size: 0.82rem; }
  .pop dl {
    margin: 0;
    display: grid;
    grid-template-columns: auto 1fr;
    gap: 0.15rem 0.6rem;
  }
  .pop dt { font-weight: 600; color: var(--muted); white-space: nowrap; }
  .pop dd { margin: 0; word-break: break-all; }
  .pop .cert-entry { padding: 0.4rem 0; border-top: 1px solid var(--border); }
  .pop .cert-label { font-weight: 600; margin-bottom: 0.2rem; }
  .summary { font-size: 0.85rem; color: var(--muted); }
  /* Responsive: stack rows vertically on small screens */
  @media (max-width: 640px) {
    table, thead, tbody, tr, th, td { display: block; width: 100%; }
    thead { display: none; }
    tr {
      margin-bottom: 0.75rem;
      border: 1px solid var(--border);
      border-radius: var(--radius);
      overflow: hidden;
    }
    td {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 0.4rem 0.75rem;
      text-align: right;
    }
    td::before {
      content: attr(data-label);
      font-weight: 600;
      font-size: 0.7rem;
      text-transform: uppercase;
      letter-spacing: 0.03em;
      color: var(--muted);
      text-align: left;
      margin-right: 1rem;
    }
    td.status-cell { justify-content: space-between; }
    .pop {
      position: fixed;
      top: 5vh;
      left: 5vw;
      right: 5vw;
      width: auto;
      max-height: 90vh;
      overflow-y: auto;
      transform: none;
    }
  }
</style>
</head>
<body>
<h1>Certificate Check Report</h1>
`)

	b.WriteString(fmt.Sprintf(`<p class="subtitle">Generated %s</p>`, time.Now().UTC().Format("2006-01-02 15:04:05 UTC")))

	var nValid, nExpired, nRevoked, nErr int
	for secIdx, sec := range sections {
		b.WriteString(fmt.Sprintf("<h2>%s</h2>\n", escapeHTML(sec.Name)))
		b.WriteString(`<table>
<thead>
<tr>
  <th style="width:auto">Issuer CN</th>
  <th style="width:7rem">Key</th>
  <th style="width:8rem">Profile</th>
  <th style="width:6rem;text-align:center">Valid</th>
  <th style="width:6rem;text-align:center">Expired</th>
  <th style="width:6rem;text-align:center">Revoked</th>
</tr>
</thead>
<tbody>
`)

		for siteIdx, s := range sec.Sites {
			b.WriteString("<tr>\n")
			b.WriteString(fmt.Sprintf(`  <td data-label="Issuer CN">%s</td>`+"\n", escapeHTML(s.IssuerCN)))
			b.WriteString(fmt.Sprintf(`  <td data-label="Key" class="mono">%s</td>`+"\n", escapeHTML(s.KeyType)))
			profile := s.Profile
			if profile == "" {
				profile = "—"
			}
			b.WriteString(fmt.Sprintf(`  <td data-label="Profile" class="meta">%s</td>`+"\n", escapeHTML(profile)))

			for _, pair := range []struct {
				r     *result
				label string
			}{
				{s.Valid, "valid"},
				{s.Expired, "expired"},
				{s.Revoked, "revoked"},
			} {
				b.WriteString(`  <td class="status-cell">`)
				if pair.r == nil {
					b.WriteString(`<span class="badge badge-none">—</span>`)
				} else {
					r := pair.r
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
					emoji, cls := statusBadge(r.Status)
					id := fmt.Sprintf("p%d-%d-%s", secIdx, siteIdx, pair.label)
					b.WriteString(fmt.Sprintf(`<details class="popover" id="%s">`, id))
					b.WriteString(fmt.Sprintf(`<summary><span class="badge %s">%s %s</span></summary>`, cls, emoji, escapeHTML(r.Status)))
					renderPopover(&b, r)
					b.WriteString(`</details>`)
				}
				b.WriteString("</td>\n")
			}
			b.WriteString("</tr>\n")
		}

		b.WriteString("</tbody>\n</table>\n")
	}

	total := nValid + nExpired + nRevoked + nErr
	b.WriteString(fmt.Sprintf(`<p class="summary">%d checked: `, total))
	b.WriteString(fmt.Sprintf(`<span style="color:var(--green)">%d valid</span>, `, nValid))
	b.WriteString(fmt.Sprintf(`<span style="color:var(--amber)">%d expired</span>, `, nExpired))
	b.WriteString(fmt.Sprintf(`<span style="color:var(--red)">%d revoked</span>`, nRevoked))
	if nErr > 0 {
		b.WriteString(fmt.Sprintf(`, <span style="color:var(--red)">%d errors</span>`, nErr))
	}
	b.WriteString("</p>\n</body>\n</html>\n")

	return b.String()
}

func renderPopover(b *strings.Builder, r *result) {
	b.WriteString(`<div class="pop">`)
	b.WriteString(fmt.Sprintf(`<h4>%s</h4>`, escapeHTML(r.Domain)))
	b.WriteString(`<dl>`)
	b.WriteString(fmt.Sprintf(`<dt>Status</dt><dd>%s</dd>`, escapeHTML(r.StatusDesc)))
	if !r.NotBefore.IsZero() {
		b.WriteString(fmt.Sprintf(`<dt>Not Before</dt><dd>%s</dd>`, r.NotBefore.UTC().Format("2006-01-02 15:04 UTC")))
		b.WriteString(fmt.Sprintf(`<dt>Not After</dt><dd>%s</dd>`, r.NotAfter.UTC().Format("2006-01-02 15:04 UTC")))
	}
	if r.CRLErr != "" {
		b.WriteString(fmt.Sprintf(`<dt>CRL Error</dt><dd>%s</dd>`, escapeHTML(r.CRLErr)))
	}
	b.WriteString(fmt.Sprintf(`<dt>In CRL</dt><dd>%v</dd>`, r.InCRL))
	b.WriteString(`</dl>`)

	if len(r.Chain) > 0 {
		b.WriteString(`<h4 style="margin-top:0.5rem">Chain</h4>`)
		for j, ci := range r.Chain {
			label := "Leaf"
			if j > 0 {
				label = fmt.Sprintf("Intermediate #%d", j)
			}
			if ci.IsCA && j == len(r.Chain)-1 {
				label = "Root / Top"
			}
			b.WriteString(fmt.Sprintf(`<div class="cert-entry"><div class="cert-label">%s</div>`, label))
			b.WriteString(`<dl>`)
			b.WriteString(fmt.Sprintf(`<dt>Subject</dt><dd>%s</dd>`, escapeHTML(ci.Subject)))
			b.WriteString(fmt.Sprintf(`<dt>Issuer</dt><dd>%s</dd>`, escapeHTML(ci.Issuer)))
			b.WriteString(fmt.Sprintf(`<dt>Serial</dt><dd class="mono">%s</dd>`, escapeHTML(ci.Serial)))
			b.WriteString(fmt.Sprintf(`<dt>Not Before</dt><dd>%s</dd>`, ci.NotBefore.UTC().Format(time.RFC3339)))
			b.WriteString(fmt.Sprintf(`<dt>Not After</dt><dd>%s</dd>`, ci.NotAfter.UTC().Format(time.RFC3339)))
			b.WriteString(fmt.Sprintf(`<dt>Key Usage</dt><dd>%s</dd>`, escapeHTML(ci.KeyUsage)))
			if len(ci.SANs) > 0 {
				b.WriteString(fmt.Sprintf(`<dt>SANs</dt><dd>%s</dd>`, escapeHTML(strings.Join(ci.SANs, ", "))))
			}
			if len(ci.CRLDistPts) > 0 {
				b.WriteString(fmt.Sprintf(`<dt>CRL</dt><dd class="mono">%s</dd>`, escapeHTML(strings.Join(ci.CRLDistPts, ", "))))
			}
			b.WriteString(`</dl></div>`)
		}
	}

	b.WriteString(`</div>`)
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
