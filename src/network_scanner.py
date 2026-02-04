#!/usr/bin/env python3
"""
Asyncio-based Network Scanner for Certificate Discovery
Container-friendly: Pure Python, no nmap, no ICMP, no root required
"""
import asyncio
import ipaddress
import logging
from dataclasses import dataclass
from typing import List, Tuple, Optional, Callable

logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    """Result of a single port scan"""
    ip: str
    port: int
    is_open: bool
    error: Optional[str] = None


@dataclass
class SweepProgress:
    """Progress tracking for sweep execution"""
    total: int
    scanned: int
    found: int
    current_ip: Optional[str] = None


class NetworkScanner:
    """Asyncio-based TCP port scanner"""

    def __init__(self,
                 timeout: float = 3.0,
                 max_concurrent: int = 100,
                 batch_size: int = 256):
        """
        Initialize scanner

        Args:
            timeout: TCP connect timeout in seconds
            max_concurrent: Maximum concurrent connections (semaphore limit)
            batch_size: Number of IPs to process before yielding progress
        """
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.batch_size = batch_size

    @staticmethod
    def parse_target(target: str) -> List[str]:
        """
        Parse CIDR notation or IP range into list of IP addresses

        Args:
            target: CIDR (e.g., "10.0.0.0/24") or range (e.g., "192.168.1.1-50")

        Returns:
            List of IP address strings
        """
        target = target.strip()

        # Handle CIDR notation (e.g., "10.0.0.0/24")
        if '/' in target:
            try:
                network = ipaddress.ip_network(target, strict=False)
                return [str(ip) for ip in network.hosts()]
            except ValueError as e:
                raise ValueError(f"Invalid CIDR notation: {target}") from e

        # Handle IP range (e.g., "192.168.1.1-50" or "192.168.1.1-192.168.1.50")
        if '-' in target:
            parts = target.split('-')
            if len(parts) != 2:
                raise ValueError(f"Invalid range format: {target}")

            start_ip_str = parts[0].strip()
            end_part = parts[1].strip()

            try:
                start_ip = ipaddress.ip_address(start_ip_str)

                # Check if end is full IP or just last octet
                if '.' in end_part or ':' in end_part:
                    # Full IP address
                    end_ip = ipaddress.ip_address(end_part)
                else:
                    # Just last octet (IPv4 only)
                    if isinstance(start_ip, ipaddress.IPv6Address):
                        raise ValueError("IPv6 range must use full addresses")

                    octets = start_ip_str.split('.')
                    octets[3] = end_part
                    end_ip = ipaddress.ip_address('.'.join(octets))

                if int(end_ip) < int(start_ip):
                    raise ValueError("End IP must be >= start IP")

                ips = []
                current = int(start_ip)
                end = int(end_ip)
                while current <= end:
                    ips.append(str(ipaddress.ip_address(current)))
                    current += 1
                return ips

            except ValueError as e:
                raise ValueError(f"Invalid IP range: {target}") from e

        # Single IP address
        try:
            ip = ipaddress.ip_address(target)
            return [str(ip)]
        except ValueError as e:
            raise ValueError(f"Invalid IP address: {target}") from e

    async def check_port(self, ip: str, port: int,
                         semaphore: asyncio.Semaphore) -> ScanResult:
        """
        Check if a TCP port is open using asyncio

        Args:
            ip: IP address to scan
            port: Port number to check
            semaphore: Concurrency limiter

        Returns:
            ScanResult with open/closed status
        """
        async with semaphore:
            try:
                # Attempt TCP connection
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=self.timeout
                )
                writer.close()
                await writer.wait_closed()
                return ScanResult(ip=ip, port=port, is_open=True)

            except asyncio.TimeoutError:
                return ScanResult(ip=ip, port=port, is_open=False,
                                  error="timeout")
            except ConnectionRefusedError:
                return ScanResult(ip=ip, port=port, is_open=False,
                                  error="refused")
            except OSError as e:
                return ScanResult(ip=ip, port=port, is_open=False,
                                  error=str(e))

    async def sweep(self,
                    target: str,
                    ports: List[int],
                    progress_callback: Optional[Callable[[SweepProgress], None]] = None
                    ) -> List[ScanResult]:
        """
        Perform network sweep and return open ports

        Args:
            target: CIDR or IP range
            ports: List of ports to scan
            progress_callback: Optional callback for progress updates

        Returns:
            List of ScanResult for open ports found
        """
        # Parse target into IP list
        ips = self.parse_target(target)
        total_scans = len(ips) * len(ports)

        logger.info(f"Starting sweep: {len(ips)} IPs x {len(ports)} ports = {total_scans} scans")

        semaphore = asyncio.Semaphore(self.max_concurrent)
        scanned = 0
        found = 0
        open_ports = []

        # Process in batches to control memory and provide progress updates
        for batch_start in range(0, len(ips), self.batch_size):
            batch_ips = ips[batch_start:batch_start + self.batch_size]

            # Create tasks for all IP:port combinations in this batch
            tasks = []
            for ip in batch_ips:
                for port in ports:
                    tasks.append(self.check_port(ip, port, semaphore))

            # Execute batch concurrently
            results = await asyncio.gather(*tasks, return_exceptions=True)

            # Process results
            for result in results:
                scanned += 1

                if isinstance(result, Exception):
                    logger.error(f"Scan error: {result}")
                    continue

                if result.is_open:
                    found += 1
                    open_ports.append(result)
                    logger.info(f"Found open port: {result.ip}:{result.port}")

            # Update progress
            if progress_callback:
                progress = SweepProgress(
                    total=total_scans,
                    scanned=scanned,
                    found=found,
                    current_ip=batch_ips[-1] if batch_ips else None
                )
                progress_callback(progress)

        logger.info(f"Sweep complete: {scanned} scanned, {found} open ports found")
        return open_ports


def validate_target(target: str) -> Tuple[bool, str, int]:
    """
    Validate a target string and return IP count

    Args:
        target: CIDR or IP range

    Returns:
        Tuple of (is_valid, error_message, ip_count)
    """
    try:
        ips = NetworkScanner.parse_target(target)
        ip_count = len(ips)

        # Warn about large ranges
        if ip_count > 65536:
            return False, f"Target too large: {ip_count} IPs (max 65536)", ip_count

        return True, "", ip_count
    except ValueError as e:
        return False, str(e), 0
