#!/usr/bin/env python3
"""
DNS Security Scanner

Checks DNS-based security records for a hostname:
- CAA (Certificate Authority Authorization)
"""
import logging
from dataclasses import dataclass, field
from typing import List, Optional

logger = logging.getLogger(__name__)

try:
    import dns.resolver
    import dns.exception
    _DNS_AVAILABLE = True
except ImportError:
    _DNS_AVAILABLE = False
    logger.warning("dnspython not installed — DNS security checks disabled")


@dataclass
class DnsResult:
    caa_present: bool = False
    caa_records: List[str] = field(default_factory=list)
    caa_checked: bool = False   # False if lookup failed/unavailable


def check_caa(hostname: str) -> DnsResult:
    """Check CAA records for *hostname*, walking up the domain hierarchy.

    CAA records are usually on the apex domain (example.com), not on
    subdomains (www.example.com). We walk upward until we find records
    or reach the TLD.
    """
    result = DnsResult()

    if not _DNS_AVAILABLE:
        return result

    # Strip port if present
    hostname = hostname.split(":")[0]

    # Skip plain IP addresses — no CAA for IPs
    import ipaddress
    try:
        ipaddress.ip_address(hostname)
        return result
    except ValueError:
        pass

    parts = hostname.rstrip(".").split(".")

    # Walk from the full hostname up to the second-level domain.
    # Stop before the TLD itself (need at least 2 labels).
    for i in range(len(parts) - 1):
        domain = ".".join(parts[i:])
        if domain.count(".") < 1:
            break  # reached TLD, stop
        try:
            answers = dns.resolver.resolve(domain, "CAA", lifetime=5)
            result.caa_present = True
            result.caa_records = [str(r) for r in answers]
            result.caa_checked = True
            logger.debug("CAA records found for %s: %s", domain, result.caa_records)
            return result
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            result.caa_checked = True
            continue
        except dns.resolver.NoNameservers:
            result.caa_checked = True
            continue
        except dns.exception.Timeout:
            logger.warning("DNS timeout checking CAA for %s", domain)
            result.caa_checked = True
            break
        except dns.exception.DNSException as exc:
            logger.warning("DNS error checking CAA for %s: %s", domain, exc)
            result.caa_checked = True
            break

    return result
