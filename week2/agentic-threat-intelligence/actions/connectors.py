import logging
import os
import base64
import json

import requests

from config import config

logger = logging.getLogger(__name__)


def _log_action(action_type: str, target: str, detail: str = "") -> str:
    prefix = "[DRY RUN] " if config.DRY_RUN else "[EXECUTED] "
    message = f"{prefix}{action_type} -> {target} {detail}".strip()
    logger.info(message)
    return message


def _post_with_retry(url: str, **kwargs) -> requests.Response:
    """Shared HTTP helper: applies the configured timeout and retries
    transient failures (network errors / 5xx) up to API_RETRY times."""
    kwargs.setdefault("timeout", config.API_TIMEOUT)
    last_exc = None

    for attempt in range(1, config.API_RETRY + 1):
        try:
            response = requests.post(url, **kwargs)
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException as exc:
            last_exc = exc
            logger.warning(
                "Request to %s failed (attempt %d/%d): %s",
                url, attempt, config.API_RETRY, exc,
            )

    raise last_exc


def block_ip(ip_address: str) -> str:
    """Block IP address via firewall API.
    Supports multiple firewall types through API abstraction."""
    if config.DRY_RUN:
        return _log_action("BLOCK_IP", ip_address)

    if not config.FIREWALL_API_URL or not config.FIREWALL_API_TOKEN:
        return _log_action("BLOCK_IP", ip_address, "(no real connector configured)")

    try:
        # Generic firewall API - adjust based on your specific firewall
        # Example payloads for common firewalls:
        # 
        # Palo Alto:
        # {"destination": ip_address, "action": "deny", "from": "trust", "to": "untrust"}
        # 
        # Fortinet:
        # {"policy": {"srcaddr": ip_address, "action": "deny", "schedule": "always"}}
        # 
        # AWS Security Groups:
        # {"group_id": "sg-xxx", "ip_ranges": [{"cidr_ip": f"{ip_address}/32"}], "rule_action": "deny"}
        
        payload = {
            "action": "deny",
            "destination": ip_address,
            "protocol": "any",
            "description": f"Auto-blocked by MedFlow threat intel - {ip_address}"
        }
        
        response = _post_with_retry(
            f"{config.FIREWALL_API_URL}/api/v1/firewall/rules",
            json=payload,
            headers={
                "Authorization": f"Bearer {config.FIREWALL_API_TOKEN}",
                "Content-Type": "application/json"
            },
        )
        
        # Log the response for audit
        logger.info(f"Firewall API response: {response.status_code} - {response.text}")
        return _log_action("BLOCK_IP", ip_address, "(firewall rule created)")
        
    except requests.exceptions.RequestException as exc:
        logger.error(f"Failed to block IP {ip_address}: {exc}")
        return _log_action("BLOCK_IP", ip_address, f"(FAILED: {str(exc)})")


def isolate_host(hostname: str) -> str:
    """Isolate host via Wazuh Active Response API."""
    if config.DRY_RUN:
        return _log_action("ISOLATE_HOST", hostname)

    if not config.WAZUH_API_URL or not config.WAZUH_USERNAME or not config.WAZUH_PASSWORD:
        return _log_action("ISOLATE_HOST", hostname, "(no real connector configured)")

    try:
        # Wazuh API v4.x Active Response endpoint
        # First, get agent ID by hostname
        agents_response = requests.get(
            f"{config.WAZUH_API_URL}/api/v4/agents",
            auth=(config.WAZUH_USERNAME, config.WAZUH_PASSWORD),
            headers={"Content-Type": "application/json"},
            timeout=config.API_TIMEOUT
        )
        agents_response.raise_for_status()
        
        agents_data = agents_response.json()
        agent_id = None
        
        # Find agent by hostname
        for agent in agents_data.get("data", {}).get("items", []):
            if agent.get("name") == hostname or agent.get("id") == hostname:
                agent_id = agent.get("id")
                break
        
        if not agent_id:
            return _log_action("ISOLATE_HOST", hostname, "(agent not found)")
        
        # Send active response command to isolate
        active_response_payload = {
            "command": "isolate-host",
            "arguments": [agent_id],
            "custom": False
        }
        
        response = _post_with_retry(
            f"{config.WAZUH_API_URL}/api/v4/active-response",
            json=active_response_payload,
            auth=(config.WAZUH_USERNAME, config.WAZUH_PASSWORD),
            headers={"Content-Type": "application/json"},
        )
        
        logger.info(f"Wazuh isolation response: {response.status_code} - {response.text}")
        return _log_action("ISOLATE_HOST", hostname, f"(isolation triggered for agent {agent_id})")
        
    except requests.exceptions.RequestException as exc:
        logger.error(f"Failed to isolate host {hostname}: {exc}")
        return _log_action("ISOLATE_HOST", hostname, f"(FAILED: {str(exc)})")


def disable_account(username: str) -> str:
    """Disable user account via IAM API (Azure AD/Entra ID, Okta, or LDAP)."""
    if config.DRY_RUN:
        return _log_action("DISABLE_ACCOUNT", username)

    # Check for Azure AD/Entra ID configuration
    azure_client_id = os.getenv("AZURE_CLIENT_ID", "")
    azure_client_secret = os.getenv("AZURE_CLIENT_SECRET", "")
    azure_tenant_id = os.getenv("AZURE_TENANT_ID", "")
    
    # Check for Okta configuration
    okta_domain = os.getenv("OKTA_DOMAIN", "")
    okta_api_token = os.getenv("OKTA_API_TOKEN", "")
    
    try:
        if azure_client_id and azure_client_secret and azure_tenant_id:
            # Azure AD/Entra ID via Microsoft Graph API
            token_url = f"https://login.microsoftonline.com/{azure_tenant_id}/oauth2/v2.0/token"
            token_payload = {
                "grant_type": "client_credentials",
                "client_id": azure_client_id,
                "client_secret": azure_client_secret,
                "scope": "https://graph.microsoft.com/.default"
            }
            
            token_response = requests.post(token_url, data=token_payload, timeout=config.API_TIMEOUT)
            token_response.raise_for_status()
            access_token = token_response.json().get("access_token")
            
            # Get user by username
            users_url = f"https://graph.microsoft.com/v1.0/users?$filter=userPrincipalName eq '{username}' or mail eq '{username}'"
            users_response = requests.get(
                users_url,
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=config.API_TIMEOUT
            )
            users_response.raise_for_status()
            
            users_data = users_response.json()
            if not users_data.get("value"):
                return _log_action("DISABLE_ACCOUNT", username, "(user not found in Azure AD)")
            
            user_id = users_data["value"][0]["id"]
            
            # Disable user
            disable_payload = {"accountEnabled": False}
            disable_response = requests.patch(
                f"https://graph.microsoft.com/v1.0/users/{user_id}",
                json=disable_payload,
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": "application/json"
                },
                timeout=config.API_TIMEOUT
            )
            disable_response.raise_for_status()
            
            return _log_action("DISABLE_ACCOUNT", username, "(account disabled in Azure AD)")
            
        elif okta_domain and okta_api_token:
            # Okta API
            users_url = f"https://{okta_domain}/api/v1/users?q={username}"
            users_response = requests.get(
                users_url,
                headers={"Authorization": f"SSWS {okta_api_token}"},
                timeout=config.API_TIMEOUT
            )
            users_response.raise_for_status()
            
            users_data = users_response.json()
            if not users_data:
                return _log_action("DISABLE_ACCOUNT", username, "(user not found in Okta)")
            
            user_id = users_data[0]["id"]
            
            # Deactivate user
            deactivate_response = requests.post(
                f"https://{okta_domain}/api/v1/users/{user_id}/lifecycle/deactivate",
                headers={"Authorization": f"SSWS {okta_api_token}"},
                timeout=config.API_TIMEOUT
            )
            deactivate_response.raise_for_status()
            
            return _log_action("DISABLE_ACCOUNT", username, "(account deactivated in Okta)")
            
        else:
            return _log_action("DISABLE_ACCOUNT", username, "(no IAM connector configured - set AZURE_* or OKTA_* env vars)")
            
    except requests.exceptions.RequestException as exc:
        logger.error(f"Failed to disable account {username}: {exc}")
        return _log_action("DISABLE_ACCOUNT", username, f"(FAILED: {str(exc)})")


def kill_process(process_ref: str) -> str:
    """Kill process via Wazuh Active Response API.
    process_ref can be PID or process name."""
    if config.DRY_RUN:
        return _log_action("KILL_PROCESS", process_ref)

    if not config.WAZUH_API_URL or not config.WAZUH_USERNAME or not config.WAZUH_PASSWORD:
        return _log_action("KILL_PROCESS", process_ref, "(no real connector configured)")

    try:
        # Wazuh kill-process active response
        # Format: kill-process <pid> or kill-process <process_name>
        active_response_payload = {
            "command": "kill-process",
            "arguments": [str(process_ref)],
            "custom": False
        }
        
        response = _post_with_retry(
            f"{config.WAZUH_API_URL}/api/v4/active-response",
            json=active_response_payload,
            auth=(config.WAZUH_USERNAME, config.WAZUH_PASSWORD),
            headers={"Content-Type": "application/json"},
        )
        
        logger.info(f"Wazuh kill-process response: {response.status_code} - {response.text}")
        return _log_action("KILL_PROCESS", process_ref, "(kill command sent)")
        
    except requests.exceptions.RequestException as exc:
        logger.error(f"Failed to kill process {process_ref}: {exc}")
        return _log_action("KILL_PROCESS", process_ref, f"(FAILED: {str(exc)})")


def quarantine_file(file_hash: str) -> str:
    """Quarantine file via EDR API (Wazuh, CrowdStrike, or SentinelOne).
    file_hash can be MD5, SHA1, or SHA256."""
    if config.DRY_RUN:
        return _log_action("QUARANTINE_FILE", file_hash)

    # Check for EDR configuration
    crowdstrike_api_url = os.getenv("CROWDSTRIKE_API_URL", "")
    crowdstrike_client_id = os.getenv("CROWDSTRIKE_CLIENT_ID", "")
    crowdstrike_client_secret = os.getenv("CROWDSTRIKE_CLIENT_SECRET", "")
    
    sentinelone_api_url = os.getenv("SENTINELONE_API_URL", "")
    sentinelone_api_token = os.getenv("SENTINELONE_API_TOKEN", "")
    
    try:
        if crowdstrike_api_url and crowdstrike_client_id and crowdstrike_client_secret:
            # CrowdStrike Falcon API
            # Get OAuth token
            token_url = f"https://api.crowdstrike.com/oauth2/token"
            token_payload = {
                "client_id": crowdstrike_client_id,
                "client_secret": crowdstrike_client_secret
            }
            token_response = requests.post(token_url, data=token_payload, timeout=config.API_TIMEOUT)
            token_response.raise_for_status()
            access_token = token_response.json().get("access_token")
            
            # Quarantine file by hash
            quarantine_payload = {
                "ids": [file_hash],
                "quarantine": True
            }
            quarantine_response = requests.post(
                f"{crowdstrike_api_url}/quarantine/entities/quarantine-machines/v1",
                json=quarantine_payload,
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": "application/json"
                },
                timeout=config.API_TIMEOUT
            )
            quarantine_response.raise_for_status()
            
            return _log_action("QUARANTINE_FILE", file_hash, "(file quarantined in CrowdStrike)")
            
        elif sentinelone_api_url and sentinelone_api_token:
            # SentinelOne API
            quarantine_payload = {
                "filter": {
                    "fileHash": [file_hash]
                },
                "data": {
                    "action": "quarantine"
                }
            }
            quarantine_response = requests.post(
                f"{sentinelone_api_url}/web/api/v2.1/actions",
                json=quarantine_payload,
                headers={
                    "Authorization": f"ApiToken {sentinelone_api_token}",
                    "Content-Type": "application/json"
                },
                timeout=config.API_TIMEOUT
            )
            quarantine_response.raise_for_status()
            
            return _log_action("QUARANTINE_FILE", file_hash, "(file quarantined in SentinelOne)")
            
        elif config.WAZUH_API_URL:
            # Wazuh - use active response to quarantine file
            # This requires custom Wazuh active response script
            active_response_payload = {
                "command": "quarantine-file",
                "arguments": [file_hash],
                "custom": False
            }
            
            response = _post_with_retry(
                f"{config.WAZUH_API_URL}/api/v4/active-response",
                json=active_response_payload,
                auth=(config.WAZUH_USERNAME, config.WAZUH_PASSWORD),
                headers={"Content-Type": "application/json"},
            )
            
            return _log_action("QUARANTINE_FILE", file_hash, "(quarantine command sent via Wazuh)")
            
        else:
            return _log_action("QUARANTINE_FILE", file_hash, "(no EDR connector configured - set CROWDSTRIKE_*, SENTINELONE_*, or WAZUH_* env vars)")
            
    except requests.exceptions.RequestException as exc:
        logger.error(f"Failed to quarantine file {file_hash}: {exc}")
        return _log_action("QUARANTINE_FILE", file_hash, f"(FAILED: {str(exc)})")


def notify_analyst(message: str) -> str:
    if config.DRY_RUN:
        return _log_action("NOTIFY_ANALYST", "", message)

    if not config.SLACK_WEBHOOK_URL:
        return _log_action("NOTIFY_ANALYST", "", f"{message} (no Slack webhook configured)")

    try:
        _post_with_retry(config.SLACK_WEBHOOK_URL, json={"text": message})
    except requests.exceptions.RequestException as exc:
        logger.error("Failed to send Slack notification: %s", exc)
        return _log_action("NOTIFY_ANALYST", "", f"{message} (Slack delivery failed)")

    return _log_action("NOTIFY_ANALYST", "", f"{message} (Slack notification sent)")


ACTION_DISPATCH = {
    "block_ip": block_ip,
    "isolate_host": isolate_host,
    "disable_account": disable_account,
    "kill_process": kill_process,
    "quarantine_file": quarantine_file,
    "notify_analyst": notify_analyst,
}