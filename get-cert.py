#!/usr/bin/env python3
import requests
import argparse
import re
import logging
import os
import sys
import time
import urllib3
import simple_acme_dns
import paramiko
from paramiko_expect import SSHClientInteraction
from dotenv import load_dotenv

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
load_dotenv()  # take environment variables from .env.

# Create the parser
parser = argparse.ArgumentParser()
# Add an argument
parser.add_argument("--host", type=str, required=True, help="Hostname of your server.")
parser.add_argument("--domain", type=str, required=True, help="Domain of your server.")
parser.add_argument(
    "-v", "--verbose", action="store_true", help="Enable verbose output."
)
parser.add_argument("-ca", action="store_true", help="Install CA certificate.")
parser.add_argument(
    "--days",
    type=int,
    help="Certificate Validity Days. Default 90 for LetsEncrypt, ZeroSSL can go up to 365.",
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
    help="Which DNS provider to use. Default is cloudflare. Options are cloudflare or digitalocean.",
    choices=["cloudflare", "digitalocean"],
    default="cloudflare",
)
parser.add_argument(
    "--sslprovider",
    help="Which SSL provider to use. Default is letsencrypt. Options are letsencrypt or zerossl.",
    choices=["letsencrypt", "zerossl"],
    default="letsencrypt",
)
# Parse the argument
args = parser.parse_args()

# Exit codes:
# 1 API tokens not set in env variables
# 2 Incorrect command line arguments
# 3 Drafting certificate failed
# 4 Adding CNAME failed
# 5 Waited too long for DNS propagation
# 6 Certificate validation failed
# 7 Certificate not ready to download
# 8 Creating CSR failed

# Get API tokens from environment variables
do_token = os.getenv("DO_KEY")
cloudflare_token = os.getenv("CF_KEY")
cloudflare_zone = os.getenv("CF_ZONE")
zerossl_token = os.getenv("ZEROSSL_KEY")
mxtoolbox_token = os.getenv("MXTOOLBOX_KEY")
uc_user = os.getenv("UC_USER")
uc_pass = os.getenv("UC_PASS")
letencrypt_email = os.getenv("LETSENCRYPT_EMAIL")
letencrypt_nameservers = ["1.1.1.1", "1.0.0.1"]

# Set base URLs for APIs
do_base = "https://api.digitalocean.com/v2/"
zerossl_base = "https://api.zerossl.com/"
cloudflare_base = "https://api.cloudflare.com/client/v4/"
mxtoolbox_base = "https://mxtoolbox.com/api/v1/"
acme_base = "https://acme-v02.api.letsencrypt.org/directory"

# Set headers for Digital Ocean
do_headers = {"Content-Type": "application/json", "Authorization": f"Bearer {do_token}"}

def draft_cert(fqdn, certificate_provider="letsencrypt", cert_days=90):
    mylogs.info("Drafting certificate")
    if certificate_provider == "zerossl":
        api_url = f"{zerossl_base}certificates?access_key={zerossl_token}"
        # Read CSR file into variable and strip out newlines
        with open(f"{fqdn}.csr", "r") as csr:
            csr_content = csr.read().replace("\n", "")
        cert_params = {
            "certificate_validity_days": cert_days,
            "certificate_domains": fqdn,
            "certificate_csr": csr_content,
        }
        # Draft certificate from ZeroSSL
        cert_req = requests.post(api_url, data=cert_params)

        # Write response to file
        resp_file = open(f"{fqdn}.resp", "w")
        resp_file.write(cert_req.text)
        resp_file.close()

        # Check if certificate was drafted successfully
        if "id" not in cert_req.json():
            mylogs.warning(f"Drafting certificate failed\n{cert_req.text}")
            sys.exit(3)
        else:
            cert_id = cert_req.json()["id"]
            mylogs.info(f"Certificate ID is: {cert_id}")
            cname_host = (
                cert_req.json()["validation"]["other_methods"][f"{fqdn}"][
                    "cname_validation_p1"
                ]
            ).replace(f".{base_domain}", "")
            mylogs.info(f"CNAME host is: {cname_host}")
            cname_value = cert_req.json()["validation"]["other_methods"][f"{fqdn}"][
                "cname_validation_p2"
            ]
            mylogs.info(f"CNAME value is: {cname_value}")

            return (cert_id, cname_host, cname_value)
    elif certificate_provider == "letsencrypt":
        client = simple_acme_dns.ACMEClient(
            domains=[fqdn],
            email=letencrypt_email,
            directory=acme_base,
            nameservers=letencrypt_nameservers,
            new_account=True,
            generate_csr=False,
        )

        # TODO: Implement loading account from file
        # client = simple_acme_dns.ACMEClient.load_account('./my_acme_account.json')
        # client.export_account_to_file(path="./", name=f"{fqdn}.json", save_certificate=False, save_private_key=False)

        # Read CSR file into variable and strip out newlines
        with open(f"{fqdn}.csr", "r") as csr:
            client.csr = csr.read().encode("utf-8")

        # Request the verification token for our DOMAIN. Print the challenge FQDN and it's corresponding token.
        resp = client.request_verification_tokens()
        # Write response to file
        resp_file = open(f"{fqdn}.resp", "w")
        resp_file.write(str(resp))
        resp_file.close()

        txt_host = list(resp.items())[0][0]
        txt_value = list(resp.items())[0][1]

        return (client, txt_host, txt_value)


def create_dns_verification(dns_name, dns_value, provider="cloudflare", type="CNAME"):
    mylogs.info("Creating DNS verification")
    if provider == "digitalocean":
        api_url = f"{do_base}domains/{base_domain}/records"

        if type == "CNAME":
            content = f'{dns_value.lower()}.'
        elif type == "TXT":
            content = f'{dns_value[0]}'

        dns_record_params = {
            "type": type,
            "name": f"{dns_name.lower()}",
            "data": content,
            "ttl": 1800,
        }
        dns_record_add = requests.post(api_url, headers=do_headers, json=dns_record_params)

        name_file = open(f"{fqdn}.name", "w")
        name_file.write(f"{dns_name}{os.linesep}")
        name_file.write(f"{dns_value}{os.linesep}")
        name_file.write(dns_record_add.text)
        name_file.close()
        if "domain_record" not in dns_record_add.json():
            mylogs.warning(f"Adding DNS Record failed\n{dns_record_add.text}")
            sys.exit(4)
        else:
            dns_record_id = dns_record_add.json()["domain_record"]["id"]
            mylogs.info(f"Created DNS Record ID: {dns_record_id}")
            return dns_record_id
    elif provider == "cloudflare":
        api_url = f"{cloudflare_base}zones/{cloudflare_zone}/dns_records"

        if type == "CNAME":
            content = f'{dns_value.lower()}.'
        elif type == "TXT":
            content = f'{dns_value[0]}'

        dns_record_params = {
            "type": type,
            "name": f"{dns_name.lower()}",
            "content": content,
            "ttl": 60,
        }
        dns_record_add = requests.post(
            api_url,
            headers={"Authorization": f"Bearer {cloudflare_token}"},
            json=dns_record_params,
        )

        name_file = open(f"{fqdn}.name", "w")
        name_file.write(f"{dns_name}{os.linesep}")
        name_file.write(f"{dns_value}{os.linesep}")
        name_file.write(dns_record_add.text)
        name_file.close()
        if "result" not in dns_record_add.json():
            mylogs.warning(f"Adding DNS Record failed\n{dns_record_add.text}")
            sys.exit(4)
        else:
            dns_record_id = dns_record_add.json()["result"]["id"]
            mylogs.info(f"Created DNS Record ID: {dns_record_id}")
            return dns_record_id

def test_dns_verification(client, dns_record):
    mylogs.info("Testing DNS verification")
    if dns_record == "CNAME":
        dns_name_propagated = "false"
        wait_time = 20
        while dns_name_propagated == "false":
            try:
                api_url = (
                    f"{mxtoolbox_base}Lookup/CNAME/?argument={cname_host}.{base_domain}"
                )
                dnslookup = requests.get(
                    api_url, headers={"Authorization": f"{mxtoolbox_token}"}
                )
            except Exception as e:
                mylogs.warning(e)
                dnslookup = ""
            if len(dnslookup.json()["Failed"]) < 1:
                mylogs.info(
                    f"CNAME found: {dnslookup.json()['Information'][0]['Canonical Name']}"
                )
                dns_name_propagated = "true"
            else:
                mylogs.info(f"Waiting for {wait_time}")
                time.sleep(wait_time)
                wait_time = wait_time * 2
                if wait_time > 320:
                    mylogs.warning("Waited too long for DNS")
                    sys.exit(5)
    elif dns_record == "TXT":
        if client.check_dns_propagation(timeout=1200, interval=5, verbose=True):
            return True
        else:
            client.deactivate_account()
            print("Failed to issue certificate for " + str(client.domains))
            exit(1)


def validate_cert(retry):
    mylogs.info("Validating certificate")
    retries = retry + 1

    api_url = (
        f"{zerossl_base}certificates/{cert_id}/challenges?access_key={zerossl_token}"
    )

    cert_vald = requests.post(api_url, data={"validation_method": "CNAME_CSR_HASH"})

    if "id" not in cert_vald.json():
        if retries == 6:
            mylogs.warning(f"Certificate validation failed\n{cert_vald.text}")
            sys.exit(6)
        else:
            mylogs.info(f"Retry {retries} for {fqdn}")
            time.sleep(10 ^ retries)
            validate_cert(retries)

    resp_file = open(f"{fqdn}.vald", "w")
    resp_file.write(cert_vald.text)
    resp_file.close()


def check_cert():
    mylogs.info("Checking certificate")
    api_url = f"{zerossl_base}certificates/{cert_id}?access_key={zerossl_token}"

    cert_issued = "false"
    wait_time = 10
    while cert_issued == "false":
        cert_verf = requests.get(api_url)
        if cert_verf.json()["status"] == "issued":
            mylogs.info("Cert is ready to download")
            cert_issued = "true"
        else:
            mylogs.info(f"Waiting for {wait_time}")
            time.sleep(wait_time)
            wait_time = wait_time * 2
            if wait_time > 320:
                mylogs.warning("Waited too long for cert to be issued")
                sys.exit(7)

def get_cert(client, provider, fqdn):
    if provider == "zerossl":
        mylogs.info("Downloading certificate")
        api_url = f"{zerossl_base}certificates/{cert_id}/download/return?access_key={zerossl_token}"

        cert = requests.get(api_url)
        cert_contents = cert.json()["certificate.crt"]
        ca_contents = cert.json()["ca_bundle.crt"]

        cert_file = open(f"{fqdn}.crt", "w")
        cert_file.write(cert.json()["certificate.crt"])
        cert_file.close()

        ca_file = open(f"{fqdn}.cas", "w")
        ca_file.write(cert.json()["ca_bundle.crt"])
        ca_file.close()

        return (cert_contents, ca_contents)
    elif provider == "letsencrypt":
        client.request_certificate()
        cert_chain = client.certificate.decode()
        out = re.findall(
            "(-----[BEGIN \S\ ]+?-----[\S\s]+?-----[END \S\ ]+?-----)", cert_chain
        )
        cert_contents = out[0]
        ca_contents = out[1]

        cert_file = open(f"{fqdn}.crt", "w")
        cert_file.write(cert_contents)
        cert_file.close()

        ca_file = open(f"{fqdn}.cas", "w")
        ca_file.write(ca_contents)
        ca_file.close()

        return (cert_contents, ca_contents)

def delete_dns_verification(provider="cloudflare"):
    mylogs.info("Deleting DNS Entry")
    if provider == "digitalocean":
        api_url = f"{do_base}domains/{base_domain}/records/{dns_record_id}"
        requests.delete(api_url, headers=do_headers)
    elif provider == "cloudflare":
        api_url = (
            f"{cloudflare_base}zones/{cloudflare_zone}/dns_records/{dns_record_id}"
        )
        requests.delete(
            api_url, headers={"Authorization": f"Bearer {cloudflare_token}"}
        )


def generate_uc_csr(server_ip, os_user, os_pass, service, domain):
    """
    gets csr from uc server
    """

    mylogs.info("Generating CSR")

    url = f"https://{server_ip}/platformcom/api/v1/certmgr/config/csr"

    headers = {"Accept": "*/*", "Content-Type": "application/json"}

    body = {"service": service, "distribution": "this-server", "commonName": domain}

    try:
        res = requests.post(
            url, headers=headers, json=body, verify=False, auth=(os_user, os_pass)
        )
        res.raise_for_status()
    except requests.exceptions.HTTPError as err:
        mylogs.warning(err)

    response = res.json()

    return response["csr"]


def upload_uc_cert(server_ip, os_user, os_pass, service, certificate):
    """
    upload signed cert to uc server
    """
    mylogs.info("Uploading signed certificate")

    url = f"https://{server_ip}/platformcom/api/v1/certmgr/config/identity/certificates"

    headers = {"Accept": "*/*", "Content-Type": "application/json"}

    body = {"service": service, "certificates": [certificate]}

    try:
        res = requests.post(
            url, headers=headers, json=body, verify=False, auth=(os_user, os_pass)
        )
        res.raise_for_status()
    except requests.exceptions.HTTPError as err:
        mylogs.warning(err)

    response = res.json()
    return response


def upload_uc_ca(server_ip, os_user, os_pass, service, certificate):
    """
    upload signed cert to uc server
    """

    mylogs.info("Uploading CA certificate")

    url = f"https://{server_ip}/platformcom/api/v1/certmgr/config/trust/certificates"

    headers = {"Accept": "*/*", "Content-Type": "application/json"}

    body = {
        "service": [service],
        "certificates": [certificate],
        "description": "ZeroSSL Trust Certificate",
    }

    try:
        res = requests.post(
            url, headers=headers, json=body, verify=False, auth=(os_user, os_pass)
        )
        res.raise_for_status()
    except requests.exceptions.HTTPError as err:
        mylogs.warning(err)

    response = res.json()
    return response


def cisco_uc_command(server_ip, os_user, os_pass, command, interaction=False):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(server_ip, username=os_user, password=os_pass)
    interact = SSHClientInteraction(ssh, timeout=90, display=True, lines_to_check=5)

    # "display=True" is just to show you what script does in real time. While in production you can set it to False
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
        time.sleep(5)  # Wait for prompt to return
        interact.send(interaction)
        interact.send("\r\n")
        interact.expect("admin:")
    else:
        interact.expect("admin:")
        interact.send(command)
        interact.expect("admin:", timeout=30)

    return "".join(interact.current_output_clean.splitlines(keepends=True)[1:]).strip()


if __name__ == "__main__":
    # Extract base_domain and fqdn from command line options
    base_domain = args.domain
    fqdn = args.host + "." + base_domain
    verbose = args.verbose
    ca = args.ca
    ssh = args.ssh
    sslprovider = args.sslprovider
    dnsprovider = args.dnsprovider

    # Setup logging
    mylogs = logging.getLogger(__name__)
    mylogs.setLevel(logging.DEBUG)

    logformat = logging.Formatter("%(asctime)s:%(levelname)s:%(message)s")

    logfile = logging.FileHandler(f"{fqdn}.log")
    logfile.setLevel(logging.INFO)
    logfile.setFormatter(logformat)

    mylogs.addHandler(logfile)

    logstream = logging.StreamHandler()
    if verbose:
        logstream.setLevel(logging.INFO)
    else:
        logstream.setLevel(logging.WARN)
    logstream.setFormatter(logformat)

    mylogs.addHandler(logstream)

    # If ssh is enabled, use ssh for certificate installation, else use API
    if ssh:
        create_csr = cisco_uc_command(
            fqdn, uc_user, uc_pass, "set csr gen tomcat", "yes"
        )

        if create_csr == "Successfully Generated CSR  for tomcat":
            mylogs.info("CSR Generated for tomcat")
            # Get the CSR from the cisco_uc
            get_csr = cisco_uc_command(
                fqdn, uc_user, uc_pass, "show csr own tomcat"
            )  # Retrieve the CSR to get cert signed
    else:
        get_csr = generate_uc_csr(fqdn, uc_user, uc_pass, "tomcat", fqdn)

    # Check if CSR was successfully retrieved
    if re.match(
        "^(?:(?!-{3,}(?:BEGIN|END) CERTIFICATE REQUEST)[\s\S])*(-{3,}BEGIN CERTIFICATE REQUEST(?:(?!-{3,}BEGIN CERTIFICATE REQUEST)[\s\S])*?-{3,}END CERTIFICATE REQUEST-{3,})\s*$",
        get_csr,
    ):
        mylogs.info("CSR successfully retrieved from cisco_uc")
        # Generate a Certificate Signing Request (CSR) using OpenSSL
        mylogs.info(f"Creating CSR {fqdn}.csr")
        csr_file = open(f"{fqdn}.csr", "w")
        csr_file.write(get_csr)
        csr_file.close()

        # Draft a certificate and extract id and cname parameters from response
        if sslprovider == "zerossl":
            cert_details = draft_cert(fqdn, sslprovider, args.days)
            cert_id = cert_details[0]
            cname_host = cert_details[1]
            cname_value = cert_details[2]
            # Add DNS entry for validation
            dns_record_id = create_dns_verification(
                cname_host, cname_value, dnsprovider, "CNAME"
            )
            # Test for propogation of CNAME
            test_dns_verification("", "CNAME")
            # Validate certificate
            validate_cert(0)
            # Check certificate available
            check_cert()
            # Download certificates from ZeroSSL
            signed_certs = get_cert("", "zerossl", fqdn)
        elif sslprovider == "letsencrypt":
            cert_details = draft_cert(fqdn, sslprovider, args.days)
            client = cert_details[0]
            txt_host = cert_details[1]
            txt_value = cert_details[2]
            # Add DNS entry for validation
            dns_record_id = create_dns_verification(
                txt_host, txt_value, dnsprovider, "TXT"
            )
            # Test for propogation of TXT
            test_dns_verification(client, "TXT")
            # Download certificates from ZeroSSL
            signed_certs = get_cert(client, "letsencrypt", fqdn)

        if ca:
            if ssh:
                upload_ca = cisco_uc_command(
                    fqdn,
                    uc_user,
                    uc_pass,
                    "set cert import trust tomcat",
                    signed_certs[1],
                )  # Install CA trust chain
                mylogs.info(upload_ca)
            else:
                upload_ca = upload_uc_ca(
                    fqdn, uc_user, uc_pass, "tomcat", signed_certs[1]
                )  # Install CA trust chain
                mylogs.info(upload_ca)

        if ssh:
            cisco_uc_command(
                fqdn, uc_user, uc_pass, "set cert import own tomcat", signed_certs[0]
            )  # Install certificate
            cisco_uc_command(
                fqdn, uc_user, uc_pass, "utils service restart Cisco Tomcat"
            )  # Restart Tomcat
            mylogs.info("Uploaded certificate. Restarting Cisco Tomcat.")
        else:
            # Upload signed certificate to Cisco UC
            upload_cert = upload_uc_cert(
                fqdn, uc_user, uc_pass, "tomcat", signed_certs[0]
            )
            # log output
            mylogs.info(upload_cert)
            mylogs.info("Please restart tomcat:  utils service restart Cisco Tomcat")

        # Tidy up CNAME
        delete_dns_verification(
            dnsprovider
        )  # Delete DNS record. Add provider argument if using Digital Ocean.
    else:
        mylogs.warning("CSR not successfully retrieved from cisco_uc")
        sys.exit(8)
