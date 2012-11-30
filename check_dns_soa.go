package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"github.com/miekg/check_dns_soa/nagios" // Needed to make it compile...
	"github.com/miekg/dns"
	"net"
	"os"
	"time"
)

// TODO gather performance data with ExchangeRtt

const (
	VERSION  string = "BETA"
	MAXERRS  uint   = 10
	MAXINFOS uint   = 100
)

var (
	timeout           time.Duration = 3 // seconds
	maxtries          uint          = 3
	warningThreshold  uint          = 1
	criticalThreshold uint          = 1
	v4only            bool          = false
	v6only            bool          = false
	requireAllServers bool          = false
	localm            *dns.Msg
	localc            *dns.Client
	conf              *dns.ClientConfig
)

func localQuery(qname string, qtype uint16) (r *dns.Msg, err error) {
	localm.Question[0] = dns.Question{qname, qtype, dns.ClassINET}
	for serverIndex := range conf.Servers {
		server := conf.Servers[serverIndex]
		r, _, err := localc.Exchange(localm, net.JoinHostPort(server, conf.Port))
		if r == nil {
			return r, err
		}
		if r.Rcode == dns.RcodeNameError {
			return r, err
		}
		if r.Rcode == dns.RcodeSuccess {
			return r, err
		}
	}
	return nil, errors.New("No name server to answer the question")
}

func testSoa(msg *dns.Msg, server string, tries uint) (soa *dns.Msg, err error) {
	c := new(dns.Client)
	c.Retry = false // TODO allow to set it to true
	c.ReadTimeout = timeout * 1e9
	tests := uint(0)
	over := false
	for !over {
		soa, _, err = c.Exchange(msg, server)
		if err != nil {
			if e, ok := err.(net.Error); ok && e.Timeout() {
				tests++
				if tests < tries {
					continue
				} else {
					over = true
				}
			} else {
				over = true
			}
		} else {
			over = true
		}
	}
	return soa, err
}

func main() {
	var (
		err           error
		errorMessages []string = make([]string, MAXERRS)
		infoMessages  []string = make([]string, MAXINFOS)
		helpBuffer    bytes.Buffer
	)
	nagios.Service = "CHECK_DNS_SOA"
	fs := flag.NewFlagSet(nagios.Service, flag.ContinueOnError)
	// http://nagiosplug.sourceforge.net/developer-guidelines.html#AEN303
	zoneP := fs.String("H", "", "DNS zone name")
	versionP := fs.Bool("V", false, "Displays the version number of the plugin")
	verbosityP := fs.Uint("v", 0, "Verbosity (from 0 to 3)")
	warningThresholdP := fs.Uint("w", warningThreshold, "Number of name servers broken to trigger a Warning")
	criticalThresholdP := fs.Uint("c", criticalThreshold, "Number of name servers broken to trigger a Critical situation")
	timeoutP := fs.Uint("t", uint(timeout), "Timeout (in seconds)")
	maxtriesP := fs.Uint("i", maxtries, "Maximum number of tests per nameserver")
	ipv4P := fs.Bool("4", v4only, "Use IPv4 only")
	ipv6P := fs.Bool("6", v6only, "Use IPv6 only")
	allServersP := fs.Bool("r", requireAllServers, "When using -4 or -6, requires that all servers have an address of this family")
	fs.SetOutput(&helpBuffer)
	fs.PrintDefaults()
	fs.Usage = func() {
		nagios.ExitStatus(nagios.UNKNOWN, "Help requested", []string{helpBuffer.String()}, true)
	}
	err = fs.Parse(os.Args[1:])
	if err != nil {
		nagios.ExitStatus(nagios.UNKNOWN, fmt.Sprintf("Error when parsing arguments: %s", err), []string{helpBuffer.String()}, true)
	}
	if *versionP {
		nagios.ExitStatus(nagios.UNKNOWN, fmt.Sprintf("Version of plugin %s is %s", os.Args[0], VERSION), nil, false)
	}
	if *ipv4P && *ipv6P {
		nagios.ExitStatus(nagios.UNKNOWN, fmt.Sprintf("-4 and -6 are not compatible"), nil, false)
	}
	if *allServersP && (!*ipv4P && !*ipv6P) {
		nagios.ExitStatus(nagios.UNKNOWN, fmt.Sprintf("-r does not make sense without -4 or -6"), nil, false)
	}
	// Not sure if this is needed, after the above flag parsing? 
	if *ipv4P {
		v4only = true
	}
	if *ipv6P {
		v6only = true
	}
	if *allServersP {
		requireAllServers = true
	}
	zone := *zoneP
	if len(zone) == 0 {
		nagios.ExitStatus(nagios.UNKNOWN, fmt.Sprintf("Usage: %s -H ZONE", os.Args[0]), nil, false)
	}
	zone = dns.Fqdn(zone)
	if *verbosityP > 3 {
		*verbosityP = 3
	}
	if *timeoutP < 1 {
		*timeoutP = 1
	}
	timeout = time.Duration(*timeoutP)
	if *maxtriesP < 1 {
		*maxtriesP = 1
	}
	maxtries = *maxtriesP
	if *warningThresholdP < 1 {
		*warningThresholdP = 1
	}
	if *criticalThresholdP < 1 {
		*criticalThresholdP = 1
	}
	if *warningThresholdP > *criticalThresholdP {
		nagios.ExitStatus(nagios.UNKNOWN, "Critical threshold must be superior to warning threshold", nil, false)
	}
	warningThreshold = *warningThresholdP
	criticalThreshold = *criticalThresholdP
	nagios.Verbosity = *verbosityP
	conf, err = dns.ClientConfigFromFile("/etc/resolv.conf")
	if conf == nil {
		nagios.ExitStatus(nagios.UNKNOWN, fmt.Sprintf("Cannot initialize the local resolver: %s", err), nil, false)
	}
	localm = new(dns.Msg)
	localm.MsgHdr.RecursionDesired = true
	localm.Question = make([]dns.Question, 1)
	localc = new(dns.Client)
	localc.ReadTimeout = timeout * 1e9
	r, err := localQuery(zone, dns.TypeNS)
	if r == nil {
		nagios.ExitStatus(nagios.CRITICAL, fmt.Sprintf("Cannot retrieve the list of name servers for %s: %s", zone, err), nil, false)
	}
	if r.Rcode == dns.RcodeNameError {
		nagios.ExitStatus(nagios.CRITICAL, fmt.Sprintf("No such domain %s", zone), nil, false)
	}
	m := new(dns.Msg)
	m.MsgHdr.RecursionDesired = false
	m.Question = make([]dns.Question, 1)
	brokenServers := uint(0)
	availableServers := uint(0)
	numNS := 0
	errors := uint(0)
	infos := uint(0)
	for i := range r.Answer {
		successServer := true
		ans := r.Answer[i]
		switch ans.(type) {
		case *dns.RR_NS:
			nameserver := ans.(*dns.RR_NS).Ns
			numNS += 1
			ips := make([]string, 0)
			infoMessages[infos] = fmt.Sprintf("%s : ", nameserver)
			if !v6only {
				ra, err := localQuery(nameserver, dns.TypeA)
				if ra == nil {
					if successServer {
						brokenServers += 1
						successServer = false
					}
					if errors < MAXERRS {
						errorMessages[errors] = fmt.Sprintf("Error getting the IPv4 address of %s: %s", nameserver, err)
						errors++
					}
					continue
				}
				if ra.Rcode != dns.RcodeSuccess {
					if successServer {
						brokenServers += 1
						successServer = false
					}
					if errors < MAXERRS {
						errorMessages[errors] = fmt.Sprintf("Error getting the IPv4 address of %s: %s", nameserver, dns.Rcode_str[ra.Rcode])
						errors++
					}
					continue
				}
				for j := range ra.Answer {
					ansa := ra.Answer[j]
					switch ansa.(type) {
					case *dns.RR_A:
						ips = append(ips, ansa.(*dns.RR_A).A.String())
					}
				}
			}
			if !v4only {
				raaaa, err := localQuery(nameserver, dns.TypeAAAA)
				if raaaa == nil {
					if successServer {
						brokenServers += 1
						successServer = false
					}
					if errors < MAXERRS {
						errorMessages[errors] = fmt.Sprintf("Error getting the IPv6 address of %s: %s", nameserver, err)
						errors++
					}
					continue
				}
				if raaaa.Rcode != dns.RcodeSuccess {
					if successServer {
						brokenServers += 1
						successServer = false
					}
					if errors < MAXERRS {
						errorMessages[errors] = fmt.Sprintf("Error getting the IPv6 address of %s: %s", nameserver, dns.Rcode_str[raaaa.Rcode])
						errors++
					}
					continue
				}
				for j := range raaaa.Answer {
					ansaaaa := raaaa.Answer[j]
					switch ansaaaa.(type) {
					case *dns.RR_AAAA:
						ips = append(ips, ansaaaa.(*dns.RR_AAAA).AAAA.String())
					}
				}
			}
			if len(ips) == 0 {
				if requireAllServers || (!v4only && !v6only) {
					if successServer {
						brokenServers += 1
						successServer = false
					}
					if errors < MAXERRS {
						ipVersion := ""
						if v4only {
							ipVersion = "v4"
						}
						if v6only {
							ipVersion = "v6"
						}
						errorMessages[errors] = fmt.Sprintf("No IP%s address for this server %s", ipVersion, nameserver)
						errors++
					}
					continue
				}
			} else {
				availableServers++
			}
			for j := range ips {
				m.Question[0] = dns.Question{zone, dns.TypeSOA, dns.ClassINET}
				nsAddressPort := net.JoinHostPort(ips[j], "53")
				soa, err := testSoa(m, nsAddressPort, maxtries)
				if soa == nil {
					if successServer {
						brokenServers += 1
						successServer = false
					}
					if errors < MAXERRS {
						errorMessages[errors] = fmt.Sprintf("Cannot get SOA from %s/%s: %s", nameserver, ips[j], err)
						errors++
					}
				} else {
					if soa.Rcode != dns.RcodeSuccess {
						if successServer {
							brokenServers += 1
							successServer = false
						}
						if errors < MAXERRS {
							errorMessages[errors] = fmt.Sprintf("%s (%s) ", ips[j], dns.Rcode_str[soa.Rcode])
							errors++
						}
					} else {
						if len(soa.Answer) == 0 { /* May happen if the server is a recursor, not authoritative, since we query with RD=0 */
							if successServer {
								brokenServers += 1
								successServer = false
							}
							if errors < MAXERRS {
								errorMessages[errors] = fmt.Sprintf("Cannot get SOA from %s/%s: 0 answer ", nameserver, ips[j])
								errors++
							}
						} else {
							rsoa := soa.Answer[0]
							switch rsoa.(type) {
							case *dns.RR_SOA:
								if soa.MsgHdr.Authoritative {
									/* TODO: test if all name servers have the same serial ? */
									infoMessages[infos] += fmt.Sprintf("%s (%d) ", ips[j], rsoa.(*dns.RR_SOA).Serial)
								} else {
									if successServer {
										brokenServers += 1
										successServer = false
									}
									if errors < MAXERRS {
										errorMessages[errors] = fmt.Sprintf("%s/%s is not authoritative", nameserver, ips[j])
										errors++
									}
								}
							}
						}
					}
				}
			}
			infos++
		}
	}
	if availableServers == 0 {
		if !v4only && !v6only {
			nagios.ExitStatus(nagios.UNKNOWN, fmt.Sprintf("Internal error: no available name servers, even without -4 and -6"), nil, false)
		}
		requestedFamily := "UNKNOWN"
		if v4only {
			requestedFamily = "IPv4"
		} else {
			requestedFamily = "IPv6"
		}
		nagios.ExitStatus(nagios.CRITICAL, fmt.Sprintf("No name servers with the requested address family %s", requestedFamily), nil, false)
	}
	if numNS == 0 {
		nagios.ExitStatus(nagios.CRITICAL, fmt.Sprintf("No NS records for \"%s\". It is probably a CNAME to a domain but not a zone", zone), nil, false)
	}
	if brokenServers < warningThreshold {
		noteWell := ""
		if brokenServers > 0 {
			noteWell = fmt.Sprintf(" (but %d broken name servers)", brokenServers)
		}
		nagios.ExitStatus(nagios.OK, fmt.Sprintf("Zone %s is fine%s", zone, noteWell), infoMessages[0:infos], false)
	} else if brokenServers < criticalThreshold {
		nagios.ExitStatus(nagios.WARNING, errorMessages[0], errorMessages[1:errors], false)
	} else {
		nagios.ExitStatus(nagios.CRITICAL, errorMessages[0], errorMessages[1:errors], false)
	}
}
