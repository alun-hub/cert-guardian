#!/usr/bin/env python3
"""
Test script for Certificate Guardian
"""
import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from scanner import TLSScanner
from database import Database
import tempfile


def test_scanner():
    """Test TLS scanner functionality"""
    print("Testing TLS Scanner...")
    scanner = TLSScanner(timeout=10)
    
    # Test scanning Google
    print("  Scanning google.com:443...")
    cert = scanner.scan_endpoint("google.com", 443)
    
    if cert:
        print(f"  ✅ Success!")
        print(f"     Subject: {cert.subject}")
        print(f"     Issuer: {cert.issuer}")
        print(f"     Expires: {cert.not_after}")
        print(f"     Fingerprint: {cert.fingerprint[:32]}...")
        
        days = scanner.get_days_until_expiry(cert.not_after)
        print(f"     Days until expiry: {int(days)}")
        return True
    else:
        print("  ❌ Failed to scan")
        return False


def test_database():
    """Test database functionality"""
    print("\nTesting Database...")
    
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
        db_path = f.name
    
    try:
        db = Database(db_path)
        
        # Test adding endpoint
        print("  Adding test endpoint...")
        endpoint_id = db.add_endpoint("test.example.com", 443, "Test Owner", "high")
        print(f"  ✅ Added endpoint with ID: {endpoint_id}")
        
        # Test adding certificate
        print("  Adding test certificate...")
        cert_id = db.add_certificate(
            fingerprint="abc123def456",
            subject="CN=test.example.com",
            issuer="CN=Test CA",
            not_before="2024-01-01T00:00:00",
            not_after="2025-12-31T23:59:59",
            serial_number="123456",
            san_list=["test.example.com", "*.test.example.com"]
        )
        print(f"  ✅ Added certificate with ID: {cert_id}")
        
        # Test adding scan
        print("  Recording scan result...")
        scan_id = db.add_scan(cert_id, endpoint_id, "success")
        print(f"  ✅ Recorded scan with ID: {scan_id}")
        
        # Test querying expiring certs
        print("  Querying expiring certificates...")
        expiring = db.get_expiring_certificates(365)
        print(f"  ✅ Found {len(expiring)} expiring certificates")
        
        db.close()
        return True
        
    finally:
        # Cleanup
        if os.path.exists(db_path):
            os.remove(db_path)


def test_config():
    """Test configuration loading"""
    print("\nTesting Configuration...")
    config_path = Path(__file__).parent / "config" / "config.yaml"
    
    if config_path.exists():
        print(f"  ✅ Config file exists: {config_path}")
        
        import yaml
        with open(config_path) as f:
            config = yaml.safe_load(f)
        
        # Check required keys
        required_keys = ['database', 'mattermost', 'endpoints', 'notifications', 'scanner']
        missing = [key for key in required_keys if key not in config]
        
        if missing:
            print(f"  ⚠️  Missing config keys: {missing}")
            return False
        else:
            print("  ✅ All required config keys present")
            print(f"  ✅ {len(config['endpoints'])} endpoints configured")
            return True
    else:
        print(f"  ❌ Config file not found: {config_path}")
        return False


def main():
    """Run all tests"""
    print("=" * 60)
    print("Certificate Guardian - Test Suite")
    print("=" * 60)
    
    results = []
    
    # Run tests
    results.append(("Scanner", test_scanner()))
    results.append(("Database", test_database()))
    results.append(("Configuration", test_config()))
    
    # Print summary
    print("\n" + "=" * 60)
    print("Test Summary")
    print("=" * 60)
    
    for name, passed in results:
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{name:20} {status}")
    
    all_passed = all(result[1] for result in results)
    
    print("\n" + "=" * 60)
    if all_passed:
        print("✅ All tests passed! System is ready.")
        print("\nNext steps:")
        print("1. Update config/config.yaml with your Mattermost webhook")
        print("2. Add your endpoints to the config")
        print("3. Run: python src/main.py --setup")
        print("4. Run: python src/main.py --once")
        return 0
    else:
        print("❌ Some tests failed. Please fix issues before running.")
        return 1


if __name__ == '__main__':
    sys.exit(main())
