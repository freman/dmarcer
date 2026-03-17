package enrichment

import (
	"strings"
	"time"

	"github.com/miekg/dns"
)

type dnsResolver struct {
	nameservers []string // with port, e.g. "1.1.1.1:53"
	timeout     time.Duration
}

func newDNSResolver(nameservers []string, timeout time.Duration) *dnsResolver {
	return &dnsResolver{
		nameservers: nameservers,
		timeout:     timeout,
	}
}

// reverseDNS performs a PTR lookup for the given IP.
// Returns "" on NXDOMAIN, timeout, or any error.
func (r *dnsResolver) reverseDNS(ip string) string {
	arpa, err := dns.ReverseAddr(ip)
	if err != nil {
		return ""
	}

	msg := new(dns.Msg)
	msg.SetQuestion(arpa, dns.TypePTR)
	msg.RecursionDesired = true

	client := &dns.Client{
		Timeout: r.timeout,
	}

	for _, ns := range r.nameservers {
		resp, _, err := client.Exchange(msg, ns)
		if err != nil {
			continue
		}

		if resp.Rcode == dns.RcodeNameError {
			// NXDOMAIN - authoritative negative answer, no point trying other servers.
			return ""
		}

		if resp.Rcode != dns.RcodeSuccess {
			continue
		}

		for _, ans := range resp.Answer {
			if ptr, ok := ans.(*dns.PTR); ok {
				name := ptr.Ptr
				name = strings.TrimSuffix(name, ".")

				return name
			}
		}
	}

	return ""
}
