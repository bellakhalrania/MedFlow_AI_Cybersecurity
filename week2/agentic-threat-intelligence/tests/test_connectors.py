#!/usr/bin/env python3
"""
test_connectors.py
Test script for security action connectors.
Tests each connector in dry-run mode by default, and can test real APIs if configured.
"""

import sys
import logging
from config import config
from actions.connectors import (
    block_ip,
    isolate_host,
    disable_account,
    kill_process,
    quarantine_file,
    notify_analyst,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def test_block_ip():
    """Test IP blocking connector."""
    logger.info("=" * 60)
    logger.info("Testing BLOCK_IP connector")
    logger.info("=" * 60)
    
    test_ip = "192.168.1.100"
    result = block_ip(test_ip)
    logger.info(f"Result: {result}")
    logger.info(f"DRY_RUN mode: {config.DRY_RUN}")
    logger.info(f"Firewall configured: {bool(config.FIREWALL_API_URL)}")
    logger.info("")


def test_isolate_host():
    """Test host isolation connector."""
    logger.info("=" * 60)
    logger.info("Testing ISOLATE_HOST connector")
    logger.info("=" * 60)
    
    test_hostname = "workstation-001"
    result = isolate_host(test_hostname)
    logger.info(f"Result: {result}")
    logger.info(f"DRY_RUN mode: {config.DRY_RUN}")
    logger.info(f"Wazuh configured: {bool(config.WAZUH_API_URL)}")
    logger.info("")


def test_disable_account():
    """Test account disabling connector."""
    logger.info("=" * 60)
    logger.info("Testing DISABLE_ACCOUNT connector")
    logger.info("=" * 60)
    
    test_username = "test.user@example.com"
    result = disable_account(test_username)
    logger.info(f"Result: {result}")
    logger.info(f"DRY_RUN mode: {config.DRY_RUN}")
    logger.info(f"Azure AD configured: {bool(config.AZURE_CLIENT_ID)}")
    logger.info(f"Okta configured: {bool(config.OKTA_DOMAIN)}")
    logger.info("")


def test_kill_process():
    """Test process killing connector."""
    logger.info("=" * 60)
    logger.info("Testing KILL_PROCESS connector")
    logger.info("=" * 60)
    
    test_pid = "12345"
    result = kill_process(test_pid)
    logger.info(f"Result: {result}")
    logger.info(f"DRY_RUN mode: {config.DRY_RUN}")
    logger.info(f"Wazuh configured: {bool(config.WAZUH_API_URL)}")
    logger.info("")


def test_quarantine_file():
    """Test file quarantine connector."""
    logger.info("=" * 60)
    logger.info("Testing QUARANTINE_FILE connector")
    logger.info("=" * 60)
    
    test_hash = "5d41402abc4b2a76b9719d911017c592"  # MD5 of "hello"
    result = quarantine_file(test_hash)
    logger.info(f"Result: {result}")
    logger.info(f"DRY_RUN mode: {config.DRY_RUN}")
    logger.info(f"CrowdStrike configured: {bool(config.CROWDSTRIKE_CLIENT_ID)}")
    logger.info(f"SentinelOne configured: {bool(config.SENTINELONE_API_URL)}")
    logger.info(f"Wazuh configured: {bool(config.WAZUH_API_URL)}")
    logger.info("")


def test_notify_analyst():
    """Test Slack notification connector."""
    logger.info("=" * 60)
    logger.info("Testing NOTIFY_ANALYST connector")
    logger.info("=" * 60)
    
    test_message = "Test alert from MedFlow threat intelligence system"
    result = notify_analyst(test_message)
    logger.info(f"Result: {result}")
    logger.info(f"DRY_RUN mode: {config.DRY_RUN}")
    logger.info(f"Slack configured: {bool(config.SLACK_WEBHOOK_URL)}")
    logger.info("")


def print_config_summary():
    """Print current connector configuration status."""
    logger.info("=" * 60)
    logger.info("CONNECTOR CONFIGURATION SUMMARY")
    logger.info("=" * 60)
    logger.info(f"DRY_RUN: {config.DRY_RUN}")
    logger.info(f"AUTO_RESPONSE_ENABLED: {config.AUTO_RESPONSE_ENABLED}")
    logger.info("")
    logger.info("Firewall:")
    logger.info(f"  API_URL: {'✓' if config.FIREWALL_API_URL else '✗'}")
    logger.info(f"  API_TOKEN: {'✓' if config.FIREWALL_API_TOKEN else '✗'}")
    logger.info("")
    logger.info("Wazuh:")
    logger.info(f"  API_URL: {'✓' if config.WAZUH_API_URL else '✗'}")
    logger.info(f"  USERNAME: {'✓' if config.WAZUH_USERNAME else '✗'}")
    logger.info(f"  PASSWORD: {'✓' if config.WAZUH_PASSWORD else '✗'}")
    logger.info("")
    logger.info("Azure AD:")
    logger.info(f"  CLIENT_ID: {'✓' if config.AZURE_CLIENT_ID else '✗'}")
    logger.info(f"  CLIENT_SECRET: {'✓' if config.AZURE_CLIENT_SECRET else '✗'}")
    logger.info(f"  TENANT_ID: {'✓' if config.AZURE_TENANT_ID else '✗'}")
    logger.info("")
    logger.info("Okta:")
    logger.info(f"  DOMAIN: {'✓' if config.OKTA_DOMAIN else '✗'}")
    logger.info(f"  API_TOKEN: {'✓' if config.OKTA_API_TOKEN else '✗'}")
    logger.info("")
    logger.info("CrowdStrike:")
    logger.info(f"  API_URL: {'✓' if config.CROWDSTRIKE_API_URL else '✗'}")
    logger.info(f"  CLIENT_ID: {'✓' if config.CROWDSTRIKE_CLIENT_ID else '✗'}")
    logger.info(f"  CLIENT_SECRET: {'✓' if config.CROWDSTRIKE_CLIENT_SECRET else '✗'}")
    logger.info("")
    logger.info("SentinelOne:")
    logger.info(f"  API_URL: {'✓' if config.SENTINELONE_API_URL else '✗'}")
    logger.info(f"  API_TOKEN: {'✓' if config.SENTINELONE_API_TOKEN else '✗'}")
    logger.info("")
    logger.info("Slack:")
    logger.info(f"  WEBHOOK_URL: {'✓' if config.SLACK_WEBHOOK_URL else '✗'}")
    logger.info("=" * 60)
    logger.info("")


def main():
    """Run all connector tests."""
    print_config_summary()
    
    # Check if we're in dry-run mode
    if config.DRY_RUN:
        logger.info("⚠️  Running in DRY_RUN mode - no real API calls will be made")
        logger.info("Set DRY_RUN=false in .env to test with real APIs")
        logger.info("")
    else:
        logger.info("⚠️  Running in LIVE mode - REAL API calls will be made!")
        logger.info("Make sure you have proper test endpoints configured")
        logger.info("")
    
    # Run tests
    try:
        test_block_ip()
        test_isolate_host()
        test_disable_account()
        test_kill_process()
        test_quarantine_file()
        test_notify_analyst()
        
        logger.info("=" * 60)
        logger.info("✓ All connector tests completed successfully")
        logger.info("=" * 60)
        
    except Exception as e:
        logger.error(f"✗ Test failed with error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
