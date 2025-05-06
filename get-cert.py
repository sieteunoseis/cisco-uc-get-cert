#!/usr/bin/env python3
import requests
from requests.auth import HTTPBasicAuth
import argparse
import re
import logging
import os
from os import path
import sys
import time
import urllib3
import simple_acme_dns
import paramiko
from paramiko_expect import SSHClientInteraction
from dotenv import load_dotenv
from abc import ABC, abstractmethod
from typing import Tuple, Optional, Dict, Any
import boto3
from azure.mgmt.dns import DnsManagementClient
from azure.identity import DefaultAzureCredential
from google.cloud import dns

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
load_dotenv()


class Logger:
    def __init__(self, fqdn: str, verbose: bool = False):
        self.log_dir = path.join("logs", fqdn)
        os.makedirs(self.log_dir, exist_ok=True)

        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)

        log_format = logging.Formatter("%(asctime)s:%(levelname)s:%(message)s")

        # File handler
        file_handler = logging.FileHandler(path.join(self.log_dir, "certificate.log"))
        file_handler.setLevel(logging.INFO)
        file_handler.setFormatter(log_format)
        self.logger.addHandler(file_handler)

        # Stream handler
        stream_handler = logging.StreamHandler()
        stream_handler.setLevel(logging.INFO if verbose else logging.WARN)
        stream_handler.setFormatter(log_format)
        self.logger.addHandler(stream_handler)

    def info(self, message: str):
        self.logger.info(message)

    def warning(self, message: str):
        self.logger.warning(message)

    def error(self, message: str):
        self.logger.error(message)


class CertificateProvider(ABC):
    def __init__(self, logger: Logger):
        self.logger = logger
        self.log_dir = logger.log_dir

    @abstractmethod
    def draft_cert(self, fqdn: str, cert_days: int) -> Tuple[str, str, str]:
        pass

    @abstractmethod
    def get_cert(self, cert_id: str, fqdn: str) -> Tuple[str, str]:
        pass


class ZeroSSLProvider(CertificateProvider):
    def __init__(self, logger: Logger, token: str):
        super().__init__(logger)
        self.token = token
        self.base_url = "https://api.zerossl.com/"

    def draft_cert(self, fqdn: str, cert_days: int) -> Tuple[str, str, str]:
        self.logger.info("Drafting certificate with ZeroSSL")
        api_url = f"{self.base_url}certificates?access_key={self.token}"

        csr_path = path.join(self.log_dir, f"{fqdn}.csr")
        with open(csr_path, "r") as csr:
            csr_content = csr.read().replace("\n", "")

        cert_params = {
            "certificate_validity_days": cert_days,
            "certificate_domains": fqdn,
            "certificate_csr": csr_content,
        }

        cert_req = requests.post(api_url, data=cert_params)

        # Save response for debugging
        resp_path = path.join(self.log_dir, f"{fqdn}.resp")
        with open(resp_path, "w") as resp_file:
            resp_file.write(cert_req.text)

        if "id" not in cert_req.json():
            self.logger.warning(f"Drafting certificate failed\n{cert_req.text}")
            sys.exit(3)

        cert_data = cert_req.json()
        cert_id = cert_data["id"]
        cname_host = cert_data["validation"]["other_methods"][fqdn][
            "cname_validation_p1"
        ]
        cname_value = cert_data["validation"]["other_methods"][fqdn][
            "cname_validation_p2"
        ]

        return cert_id, cname_host.replace(f".{fqdn.split('.', 1)[1]}", ""), cname_value

    def get_cert(self, cert_id: str, fqdn: str) -> Tuple[str, str]:
        self.logger.info("Downloading certificate from ZeroSSL")
        api_url = f"{self.base_url}certificates/{cert_id}/download/return?access_key={self.token}"

        cert = requests.get(api_url)
        cert_contents = cert.json()["certificate.crt"]
        ca_contents = cert.json()["ca_bundle.crt"]

        # Save certificates to files in logs directory
        cert_path = path.join(self.log_dir, f"{fqdn}.crt")
        ca_path = path.join(self.log_dir, f"{fqdn}.cas")

        with open(cert_path, "w") as cert_file:
            cert_file.write(cert_contents)

        with open(ca_path, "w") as ca_file:
            ca_file.write(ca_contents)

        return cert_contents, ca_contents

    def validate_cert(self, cert_id: str, retry: int = 0) -> bool:
        self.logger.info("Validating certificate")
        retries = retry + 1

        api_url = (
            f"{self.base_url}certificates/{cert_id}/challenges?access_key={self.token}"
        )
        cert_vald = requests.post(api_url, data={"validation_method": "CNAME_CSR_HASH"})

        if "id" not in cert_vald.json():
            if retries == 6:
                self.logger.warning(f"Certificate validation failed\n{cert_vald.text}")
                sys.exit(6)
            else:
                self.logger.info(f"Retry {retries}")
                time.sleep(10**retries)
                return self.validate_cert(cert_id, retries)

        vald_path = path.join(self.log_dir, f"{cert_id}.vald")
        with open(vald_path, "w") as resp_file:
            resp_file.write(cert_vald.text)

        return True

    def check_cert_status(self, cert_id: str) -> bool:
        self.logger.info("Checking certificate status")
        api_url = f"{self.base_url}certificates/{cert_id}?access_key={self.token}"

        wait_time = 10
        while True:
            cert_verf = requests.get(api_url)
            if cert_verf.json()["status"] == "issued":
                self.logger.info("Certificate is ready to download")
                return True

            self.logger.info(f"Waiting {wait_time} seconds...")
            time.sleep(wait_time)
            wait_time *= 2

            if wait_time > 320:
                self.logger.warning("Timeout waiting for certificate to be issued")
                sys.exit(7)


class LetsEncryptProvider(CertificateProvider):
    def __init__(
        self,
        logger: Logger,
        email: str,
        nameservers: list,
        account_dir: str = "accounts",
    ):
        super().__init__(logger)
        self.email = email
        self.nameservers = nameservers
        self.acme_base = "https://acme-v02.api.letsencrypt.org/directory"
        self.account_dir = account_dir
        os.makedirs(self.account_dir, exist_ok=True)

    def _get_account_path(self, fqdn: str) -> str:
        """Get the path for the account file for a given domain"""
        safe_name = re.sub(r"[^a-zA-Z0-9-]", "_", fqdn)
        return path.join(self.account_dir, f"{safe_name}_account.json")

    def _load_existing_account(self, fqdn: str) -> Optional[simple_acme_dns.ACMEClient]:
        """Try to load an existing ACME account for the domain"""
        account_path = self._get_account_path(fqdn)

        if path.exists(account_path):
            try:
                self.logger.info(
                    f"Loading existing Let's Encrypt account from {account_path}"
                )
                return simple_acme_dns.ACMEClient.load_account_from_file(account_path)
            except Exception as e:
                self.logger.warning(f"Failed to load existing account: {str(e)}")
                sys.exit(8)
                return None
        return None

    def draft_cert(self, fqdn: str, cert_days: int) -> Tuple[Any, str, str]:
        self.logger.info("Drafting certificate with Let's Encrypt")

        # Try to load existing account first
        client = self._load_existing_account(fqdn)

        if client is None:
            self.logger.info("Creating new Let's Encrypt account")
            client = simple_acme_dns.ACMEClient(
                domains=[fqdn],
                email=self.email,
                directory=self.acme_base,
                nameservers=self.nameservers,
                new_account=True,
                generate_csr=False,
            )

            # Save the new account
            account_path = self._get_account_path(fqdn)
            self.logger.info(f"Saving new account to {account_path}")
            client.export_account_to_file(
                path=self.account_dir,
                name=path.basename(account_path),
                save_certificate=False,
                save_private_key=True,
            )
        else:
            client.nameservers = self.nameservers

        csr_path = path.join(self.log_dir, f"{fqdn}.csr")
        with open(csr_path, "r") as csr:
            client.csr = csr.read().encode("utf-8")

        self.logger.info("Requesting verification tokens from Let's Encrypt")
        resp = client.request_verification_tokens()

        # Save response for debugging
        resp_path = path.join(self.log_dir, f"{fqdn}.resp")
        with open(resp_path, "w") as resp_file:
            resp_file.write(str(resp))
        
        # Validate response before extracting values
        if resp is None:
            self.logger.error("Failed to get verification tokens: Response is None")
            sys.exit(8)
            
        if not resp or not hasattr(resp, 'items') or not resp.items():
            self.logger.error(f"Invalid response from Let's Encrypt: {resp}")
            sys.exit(8)
            
        # Extract DNS validation details safely
        try:
            items = list(resp.items())
            if not items:
                self.logger.error("No verification tokens returned from Let's Encrypt")
                sys.exit(8)
                
            txt_host = items[0][0]
            txt_value = items[0][1]
            
            self.logger.info(f"Received verification token - Host: {txt_host}, Value: {txt_value}")
        except (IndexError, AttributeError, TypeError) as e:
            self.logger.error(f"Failed to extract verification tokens: {str(e)}")
            self.logger.error(f"Response content: {resp}")
            sys.exit(8)

        return client, txt_host, txt_value

    def get_cert(self, client: Any, fqdn: str) -> Tuple[str, str]:
        self.logger.info("Getting certificate from Let's Encrypt")
        client.request_certificate(wait=10, timeout=90)
        cert_chain = client.certificate.decode()
        certs = re.findall(r"(-----[BEGIN \S\ ]+?-----[\S\s]+?-----[END \S\ ]+?-----)", cert_chain)

        # Save certificates to files in logs directory
        cert_path = path.join(self.log_dir, f"{fqdn}.crt")
        ca_path = path.join(self.log_dir, f"{fqdn}.cas")

        with open(cert_path, "w") as cert_file:
            cert_file.write(certs[0])

        with open(ca_path, "w") as ca_file:
            ca_file.write(certs[1])

        return certs[0], certs[1]


class DNSProvider(ABC):
    def __init__(self, logger: Logger):
        self.logger = logger
        self.log_dir = logger.log_dir

    @abstractmethod
    def create_verification(
        self, dns_name: str, dns_value: str, record_type: str
    ) -> str:
        pass

    @abstractmethod
    def delete_verification(self, record_id: str):
        pass


class DNSVerification:
    def __init__(self, logger: Logger, mxtoolbox_token: str):
        self.logger = logger
        self.mxtoolbox_token = mxtoolbox_token
        self.base_url = "https://mxtoolbox.com/api/v1/"

    def verify_cname(self, cname_host: str, base_domain: str) -> bool:
        dns_name_propagated = False
        wait_time = 20

        while not dns_name_propagated:
            try:
                api_url = (
                    f"{self.base_url}Lookup/CNAME/?argument={cname_host}.{base_domain}"
                )
                dnslookup = requests.get(
                    api_url, headers={"Authorization": self.mxtoolbox_token}
                )

                if len(dnslookup.json()["Failed"]) < 1:
                    self.logger.info(
                        f"CNAME found: {dnslookup.json()['Information'][0]['Canonical Name']}"
                    )
                    return True
            except Exception as e:
                self.logger.warning(str(e))

            self.logger.info(f"Waiting {wait_time} seconds")
            time.sleep(wait_time)
            wait_time *= 2

            if wait_time > 320:
                self.logger.warning("DNS propagation timeout")
                sys.exit(5)

        return False


class CloudflareProvider(DNSProvider):
    def __init__(self, logger: Logger, token: str, zone: str):
        super().__init__(logger)
        self.token = token
        self.zone = zone
        self.base_url = "https://api.cloudflare.com/client/v4/"

    def create_verification(
        self, dns_name: str, dns_value: str, record_type: str
    ) -> str:
        self.logger.info(f"Creating {record_type} record in Cloudflare")
        api_url = f"{self.base_url}zones/{self.zone}/dns_records"

        if record_type == "CNAME":
            content = f"{dns_value.lower()}."
        elif record_type == "TXT":
            content = dns_value[0] if isinstance(dns_value, list) else dns_value

        dns_record_params = {
            "type": record_type,
            "name": dns_name.lower(),
            "content": content,
            "ttl": 60,
        }

        response = requests.post(
            api_url,
            headers={"Authorization": f"Bearer {self.token}"},
            json=dns_record_params,
        )

        # Save record info for debugging in logs directory
        name_path = path.join(self.log_dir, f"{dns_name}.name")
        with open(name_path, "w") as name_file:
            name_file.write(f"{dns_name}\n{dns_value}\n{response.text}")

        if "result" not in response.json():
            self.logger.warning(f"Adding DNS Record failed\n{response.text}")
            sys.exit(4)

        record_id = response.json()["result"]["id"]
        self.logger.info(f"Created DNS Record ID: {record_id}")
        return record_id

    def delete_verification(self, record_id: str):
        self.logger.info("Deleting DNS record from Cloudflare")
        api_url = f"{self.base_url}zones/{self.zone}/dns_records/{record_id}"
        requests.delete(api_url, headers={"Authorization": f"Bearer {self.token}"})


class DigitalOceanProvider(DNSProvider):
    def __init__(self, logger: Logger, token: str, base_domain: str):
        super().__init__(logger)
        self.token = token
        self.base_domain = base_domain
        self.base_url = "https://api.digitalocean.com/v2/"
        self.headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        }

    def create_verification(
        self, dns_name: str, dns_value: str, record_type: str
    ) -> str:
        self.logger.info(f"Creating {record_type} record in DigitalOcean")
        api_url = f"{self.base_url}domains/{self.base_domain}/records"

        # Strip the base domain from the dns_name if it's present
        if dns_name.endswith(f".{self.base_domain}"):
            dns_name = dns_name[: -len(f".{self.base_domain}")]

        if record_type == "CNAME":
            content = f"{dns_value.lower()}."
        elif record_type == "TXT":
            content = dns_value[0] if isinstance(dns_value, list) else dns_value

        dns_record_params = {
            "type": record_type,
            "name": dns_name.lower(),
            "data": content,
            "ttl": 30,
        }

        response = requests.post(api_url, headers=self.headers, json=dns_record_params)

        name_path = path.join(self.log_dir, f"{dns_name}.name")
        with open(name_path, "w") as name_file:
            name_file.write(f"{dns_name}\n{dns_value}\n{response.text}")

        if "domain_record" not in response.json():
            self.logger.warning(f"Adding DNS Record failed\n{response.text}")
            sys.exit(4)

        record_id = response.json()["domain_record"]["id"]
        self.logger.info(f"Created DNS Record ID: {record_id}")
        return record_id

    def delete_verification(self, record_id: str):
        self.logger.info("Deleting DNS record from DigitalOcean")
        api_url = f"{self.base_url}domains/{self.base_domain}/records/{record_id}"
        requests.delete(api_url, headers=self.headers)


class Route53Provider(DNSProvider):
    def __init__(self, logger: Logger, access_key: str, secret_key: str, zone_id: str):
        super().__init__(logger)
        self.client = boto3.client(
            "route53", aws_access_key_id=access_key, aws_secret_access_key=secret_key
        )
        self.zone_id = zone_id

    def create_verification(
        self, dns_name: str, dns_value: str, record_type: str
    ) -> str:
        self.logger.info(f"Creating {record_type} record in Route53")

        if record_type == "CNAME":
            content = f"{dns_value.lower()}."
        elif record_type == "TXT":
            content = dns_value[0] if isinstance(dns_value, list) else dns_value
            content = f'"{content}"'  # Route53 requires TXT values to be quoted

        try:
            response = self.client.change_resource_record_sets(
                HostedZoneId=self.zone_id,
                ChangeBatch={
                    "Changes": [
                        {
                            "Action": "UPSERT",
                            "ResourceRecordSet": {
                                "Name": dns_name.lower(),
                                "Type": record_type,
                                "TTL": 60,
                                "ResourceRecords": [{"Value": content}],
                            },
                        }
                    ]
                },
            )

            # Save record info for debugging
            name_path = path.join(self.log_dir, f"{dns_name}.name")
            with open(name_path, "w") as name_file:
                name_file.write(f"{dns_name}\n{dns_value}\n{str(response)}")

            record_id = f"{record_type}:{dns_name}"  # Route53 doesn't return record IDs
            self.logger.info(f"Created DNS Record: {record_id}")
            return record_id

        except Exception as e:
            self.logger.warning(f"Adding DNS Record failed\n{str(e)}")
            raise

    def delete_verification(self, record_id: str):
        self.logger.info("Deleting DNS record from Route53")
        record_type, dns_name = record_id.split(":", 1)

        try:
            self.client.change_resource_record_sets(
                HostedZoneId=self.zone_id,
                ChangeBatch={
                    "Changes": [
                        {
                            "Action": "DELETE",
                            "ResourceRecordSet": {
                                "Name": dns_name.lower(),
                                "Type": record_type,
                                "TTL": 60,
                                "ResourceRecords": [
                                    {"Value": '""'}
                                ],  # Value is required but will be ignored
                            },
                        }
                    ]
                },
            )
        except Exception as e:
            self.logger.warning(f"Failed to delete DNS record: {str(e)}")


class AzureDNSProvider(DNSProvider):
    def __init__(
        self, logger: Logger, subscription_id: str, resource_group: str, zone_name: str
    ):
        super().__init__(logger)
        self.credential = DefaultAzureCredential()
        self.client = DnsManagementClient(self.credential, subscription_id)
        self.resource_group = resource_group
        self.zone_name = zone_name

    def create_verification(
        self, dns_name: str, dns_value: str, record_type: str
    ) -> str:
        self.logger.info(f"Creating {record_type} record in Azure DNS")

        # Remove zone name from the record name if present
        if dns_name.endswith(f".{self.zone_name}"):
            relative_name = dns_name[: -len(f".{self.zone_name}")]
        else:
            relative_name = dns_name

        try:
            if record_type == "CNAME":
                parameters = {
                    "ttl": 60,
                    "cname_record": {"cname": f"{dns_value.lower()}."},
                }
            else:  # TXT record
                content = dns_value[0] if isinstance(dns_value, list) else dns_value
                parameters = {"ttl": 60, "txt_records": [{"value": [content]}]}

            record_set = self.client.record_sets.create_or_update(
                self.resource_group,
                self.zone_name,
                relative_name,
                record_type,
                parameters,
            )

            # Save record info for debugging
            name_path = path.join(self.log_dir, f"{dns_name}.name")
            with open(name_path, "w") as name_file:
                name_file.write(f"{dns_name}\n{dns_value}\n{str(record_set)}")

            record_id = f"{record_type}:{relative_name}"
            self.logger.info(f"Created DNS Record: {record_id}")
            return record_id

        except Exception as e:
            self.logger.warning(f"Adding DNS Record failed\n{str(e)}")
            raise

    def delete_verification(self, record_id: str):
        self.logger.info("Deleting DNS record from Azure DNS")
        record_type, name = record_id.split(":", 1)

        try:
            self.client.record_sets.delete(
                self.resource_group, self.zone_name, name, record_type
            )
        except Exception as e:
            self.logger.warning(f"Failed to delete DNS record: {str(e)}")


class GoogleCloudDNSProvider(DNSProvider):
    def __init__(self, logger: Logger, project_id: str, zone_name: str):
        super().__init__(logger)
        self.client = dns.Client(project=project_id)
        self.zone = self.client.zone(zone_name)

    def create_verification(
        self, dns_name: str, dns_value: str, record_type: str
    ) -> str:
        self.logger.info(f"Creating {record_type} record in Google Cloud DNS")

        if record_type == "CNAME":
            content = f"{dns_value.lower()}."
        elif record_type == "TXT":
            content = dns_value[0] if isinstance(dns_value, list) else dns_value

        try:
            record_set = self.zone.resource_record_set(
                dns_name.lower(), record_type, 60, [content]
            )

            changes = self.zone.changes()
            changes.add_record_set(record_set)
            changes.create()

            # Save record info for debugging
            name_path = path.join(self.log_dir, f"{dns_name}.name")
            with open(name_path, "w") as name_file:
                name_file.write(
                    f"{dns_name}\n{dns_value}\n{str(record_set.properties())}"
                )

            record_id = f"{record_type}:{dns_name}"
            self.logger.info(f"Created DNS Record: {record_id}")
            return record_id

        except Exception as e:
            self.logger.warning(f"Adding DNS Record failed\n{str(e)}")
            raise

    def delete_verification(self, record_id: str):
        self.logger.info("Deleting DNS record from Google Cloud DNS")
        record_type, name = record_id.split(":", 1)

        try:
            record_set = self.zone.resource_record_set(
                name.lower(), record_type, 60, [""]  # Empty content for deletion
            )

            changes = self.zone.changes()
            changes.delete_record_set(record_set)
            changes.create()
        except Exception as e:
            self.logger.warning(f"Failed to delete DNS record: {str(e)}")

class CiscoUCProvider:
    def __init__(self, logger: Logger, host: str, username: str, password: str):
        self.logger = logger
        self.host = host
        self.username = username
        self.password = password

    def get_certs(self) -> str:
        self.logger.info("Collecting Certificates")
        url = f"https://{self.host}/platformcom/api/v1/certmgr/config/snapshot/server"

        try:
            response = requests.get(
                url, verify=False, auth=HTTPBasicAuth(self.username, self.password)
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as err:
            self.logger.error(f"Failed to get certificates: {err}")
            sys.exit(8)

    def generate_csr(self, service: str, domain: str) -> str:
        self.logger.info("Generating CSR")
        url = f"https://{self.host}/platformcom/api/v1/certmgr/config/csr"

        headers = {"Accept": "*/*", "Content-Type": "application/json"}
        body = {"service": service, "distribution": "this-server", "commonName": domain}

        try:
            response = requests.post(
                url,
                headers=headers,
                json=body,
                verify=False,
                auth=(self.username, self.password),
            )
            response.raise_for_status()
            return response.json()["csr"]
        except requests.exceptions.HTTPError as err:
            self.logger.error(f"Failed to generate CSR: {err}")
            sys.exit(8)

    def upload_cert(self, service: str, certificate: str) -> Dict:
        self.logger.info("Uploading certificate")
        url = f"https://{self.host}/platformcom/api/v1/certmgr/config/identity/certificates"

        headers = {"Accept": "*/*", "Content-Type": "application/json"}
        body = {"service": service, "certificates": [certificate]}

        try:
            response = requests.post(
                url,
                headers=headers,
                json=body,
                verify=False,
                auth=(self.username, self.password),
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as err:
            self.logger.error(f"Failed to upload certificate: {err}")
            return {"error": str(err)}

    def upload_ca(self, service: str, certificate: str) -> Dict:
        self.logger.info("Uploading CA certificate")
        url = (
            f"https://{self.host}/platformcom/api/v1/certmgr/config/trust/certificates"
        )

        headers = {"Accept": "*/*", "Content-Type": "application/json"}
        body = {
            "service": [service],
            "certificates": [certificate],
            "description": "Trust Certificate",
        }

        try:
            response = requests.post(
                url,
                headers=headers,
                json=body,
                verify=False,
                auth=(self.username, self.password),
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as err:
            self.logger.error(f"Failed to upload CA certificate: {err}")
            return {"error": str(err)}

    def ssh_command(self, command: str, interaction: str = None) -> str:
        """Execute SSH command on Cisco UC server"""
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(self.host, username=self.username, password=self.password)

        interact = SSHClientInteraction(ssh, timeout=90, display=True, lines_to_check=5)

        if interaction:
            interact.expect("admin:")
            interact.send(command)
            interact.expect(
                [
                    ".*Paste the Certificate and Hit Enter.*",
                    ".*Include OU in CSR (yes|no)?.*",
                ],
                timeout=10,
            )
            time.sleep(5)
            interact.send(interaction)
            interact.send("\r\n")
            interact.expect("admin:")
        else:
            interact.expect("admin:")
            interact.send(command)
            interact.expect("admin:", timeout=30)

        return "".join(
            interact.current_output_clean.splitlines(keepends=True)[1:]
        ).strip()


def main():
    parser = argparse.ArgumentParser(description="Certificate management for Cisco UC")
    parser.add_argument(
        "--host", type=str, required=True, help="Hostname of your server"
    )
    parser.add_argument(
        "--domain", type=str, required=True, help="Domain of your server"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose output"
    )
    parser.add_argument("-ca", action="store_true", help="Install CA certificate")
    parser.add_argument(
        "--days",
        type=int,
        help="Certificate Validity Days. Default 90 for LetsEncrypt, ZeroSSL can go up to 365",
        default=90,
        choices=[90, 365],
    )
    parser.add_argument(
        "--ssh",
        action="store_true",
        help="Use ssh for certificate installation instead of API (Pre 14.x versions and UCCX)",
    )
    parser.add_argument(
        "--dnsprovider",
        help="Which DNS provider to use. Default is cloudflare",
        choices=["cloudflare", "digitalocean", "route53", "azure", "google"],
        default="cloudflare",
    )
    parser.add_argument(
        "--sslprovider",
        help="Which SSL provider to use. Default is letsencrypt",
        choices=["letsencrypt", "zerossl"],
        default="letsencrypt",
    )

    args = parser.parse_args()

    # Setup base domain and FQDN
    base_domain = args.domain
    fqdn = f"{args.host}.{base_domain}"

    # Initialize logger
    logger = Logger(fqdn, args.verbose)

    try:
        # Verify required environment variables
        if args.dnsprovider == "digitalocean" and not os.getenv("DO_KEY"):
            logger.error("DigitalOcean API token not set in environment")
            sys.exit(1)
        elif args.dnsprovider == "cloudflare" and (
            not os.getenv("CF_KEY") or not os.getenv("CF_ZONE")
        ):
            logger.error("Cloudflare API token or zone ID not set in environment")
            sys.exit(1)
        elif args.dnsprovider == "route53" and (
            not os.getenv("AWS_ACCESS_KEY")
            or not os.getenv("AWS_SECRET_KEY")
            or not os.getenv("AWS_ZONE_ID")
        ):
            logger.error("AWS credentials or zone ID not set in environment")
            sys.exit(1)
        elif args.dnsprovider == "azure" and (
            not os.getenv("AZURE_SUBSCRIPTION_ID")
            or not os.getenv("AZURE_RESOURCE_GROUP")
            or not os.getenv("AZURE_ZONE_NAME")
        ):
            logger.error("Azure configuration not set in environment")
            sys.exit(1)
        elif args.dnsprovider == "google" and (
            not os.getenv("GOOGLE_PROJECT_ID") or not os.getenv("GOOGLE_ZONE_NAME")
        ):
            logger.error("Google Cloud configuration not set in environment")
            sys.exit(1)

        if args.sslprovider == "zerossl" and not os.getenv("ZEROSSL_KEY"):
            logger.error("ZeroSSL API token not set in environment")
            sys.exit(1)
        elif args.sslprovider == "letsencrypt" and not os.getenv("LETSENCRYPT_EMAIL"):
            logger.error("Let's Encrypt email not set in environment")
            sys.exit(1)

        # Initialize Cisco UC provider
        cisco_uc = CiscoUCProvider(
            logger, fqdn, os.getenv("UC_USER"), os.getenv("UC_PASS")
        )

        # Generate CSR
        if args.ssh:
            logger.info("Generating CSR via SSH")
            create_csr = cisco_uc.ssh_command("set csr gen tomcat", "yes")
            if create_csr == "Successfully Generated CSR for tomcat":
                logger.info("CSR Generated for tomcat")
                get_csr = cisco_uc.ssh_command("show csr own tomcat")
        else:
            logger.info("Generating CSR via API")
            get_csr = cisco_uc.generate_csr("tomcat", fqdn)

        # Validate CSR format
        if not re.match(
            r"^(?:(?!-{3,}(?:BEGIN|END) CERTIFICATE REQUEST)[\s\S])*(-{3,}BEGIN CERTIFICATE REQUEST(?:(?!-{3,}BEGIN CERTIFICATE REQUEST)[\s\S])*?-{3,}END CERTIFICATE REQUEST-{3,})\s*$",
            get_csr,
        ):
            logger.error("Invalid CSR format")
            sys.exit(8)

        # Save CSR to file in logs directory
        csr_path = path.join(logger.log_dir, f"{fqdn}.csr")
        with open(csr_path, "w") as csr_file:
            csr_file.write(get_csr)

        # Initialize certificate provider
        if args.sslprovider == "zerossl":
            cert_provider = ZeroSSLProvider(logger, os.getenv("ZEROSSL_KEY"))
        else:
            cert_provider = LetsEncryptProvider(
                logger,
                os.getenv("LETSENCRYPT_EMAIL"),
                [os.getenv("LETSENCRYPT_DNS_1"), os.getenv("LETSENCRYPT_DNS_2")],
            )

        # Initialize DNS provider
        if args.dnsprovider == "digitalocean":
            dns_provider = DigitalOceanProvider(
                logger, os.getenv("DO_KEY"), base_domain
            )
        elif args.dnsprovider == "route53":
            dns_provider = Route53Provider(
                logger,
                os.getenv("AWS_ACCESS_KEY"),
                os.getenv("AWS_SECRET_KEY"),
                os.getenv("AWS_ZONE_ID"),
            )
        elif args.dnsprovider == "azure":
            dns_provider = AzureDNSProvider(
                logger,
                os.getenv("AZURE_SUBSCRIPTION_ID"),
                os.getenv("AZURE_RESOURCE_GROUP"),
                os.getenv("AZURE_ZONE_NAME"),
            )
        elif args.dnsprovider == "google":
            dns_provider = GoogleCloudDNSProvider(
                logger, os.getenv("GOOGLE_PROJECT_ID"), os.getenv("GOOGLE_ZONE_NAME")
            )
        else:
            dns_provider = CloudflareProvider(
                logger, os.getenv("CF_KEY"), os.getenv("CF_ZONE")
            )

        # Initialize DNS verification
        dns_verifier = DNSVerification(logger, os.getenv("MXTOOLBOX_KEY"))

        # Get certificate
        if args.sslprovider == "zerossl":
            # Draft certificate with ZeroSSL
            cert_id, cname_host, cname_value = cert_provider.draft_cert(fqdn, args.days)

            # Create DNS verification
            dns_record_id = dns_provider.create_verification(
                cname_host, cname_value, "CNAME"
            )

            # Verify DNS propagation
            dns_verifier.verify_cname(cname_host, base_domain)

            # Validate and check certificate
            cert_provider.validate_cert(cert_id)
            cert_provider.check_cert_status(cert_id)

            # Get the certificates
            cert_contents, ca_contents = cert_provider.get_cert(cert_id, fqdn)
        else:
            # Draft certificate with Let's Encrypt
            client, txt_host, txt_value = cert_provider.draft_cert(fqdn, args.days)

            # Create DNS verification
            dns_record_id = dns_provider.create_verification(txt_host, txt_value, "TXT")

            # Wait for DNS propagation
            if not client.check_dns_propagation(timeout=1200, interval=5, verbose=True):
                logger.error("DNS propagation failed")
                client.deactivate_account()
                sys.exit(5)

            # Get the certificates
            cert_contents, ca_contents = cert_provider.get_cert(client, fqdn)

        # Install certificates
        if args.ca:
            if args.ssh:
                upload_ca = cisco_uc.ssh_command(
                    "set cert import trust tomcat", ca_contents
                )
                logger.info(f"CA certificate installation: {upload_ca}")
            else:
                upload_ca = cisco_uc.upload_ca("tomcat", ca_contents)
                logger.info(f"CA certificate installation: {upload_ca}")

        if args.ssh:
            cisco_uc.ssh_command("set cert import own tomcat", cert_contents)
            cisco_uc.ssh_command("utils service restart Cisco Tomcat")
            logger.info("Certificate installed. Tomcat service restarted.")
        else:
            upload_cert = cisco_uc.upload_cert("tomcat", cert_contents)
            logger.info(f"Certificate installation: {upload_cert}")
            logger.info("Please restart tomcat: utils service restart Cisco Tomcat")

        # Clean up DNS verification
        dns_provider.delete_verification(dns_record_id)

    except Exception as e:
        logger.error(f"An error occurred: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
