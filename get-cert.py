#!/usr/bin/env python3
import dns.resolver
import requests
import argparse
import re
import logging
import os
import sys
import time
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import paramiko
from paramiko_expect import SSHClientInteraction
from dotenv import load_dotenv

load_dotenv()  # take environment variables from .env.

# Create the parser
parser = argparse.ArgumentParser()
# Add an argument
parser.add_argument('--host', type=str, required=True, help='Hostname of your server.')
parser.add_argument('--domain', type=str, required=True, help='Domain of your server.')
parser.add_argument('-v',"--verbose", action='store_true', help='Enable verbose output.')
parser.add_argument('-ca', action='store_true', help='Install CA certificate.')
parser.add_argument('--days', type=int, help='Certificate Validity Days, default 90.')
parser.add_argument('--ssh', action='store_true', help='Use ssh for certificate installation instead of API (Pre 14.x versions and UCCX)')
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
do_token = os.getenv('DO_KEY')
zerossl_token = os.getenv('ZEROSSL_KEY')
uc_user = os.getenv('UC_USER')
uc_pass = os.getenv('UC_PASS')

if not "DO_KEY" in os.environ and "ZEROSSL_KEY" not in os.environ\
    and "UC_USER" not in os.environ and "UC_PASS" not in os.environ:

    print("""
    Error: missing one or more environment variables.
    Please ensure you've defined the following:
    DO_KEY`
    ZEROSSL_KEY
    UC_USER
    UC_PASS
    """)
    sys.exit(1)

# Set base URLs for APIs
do_base = 'https://api.digitalocean.com/v2/'
zerossl_base = 'https://api.zerossl.com/'

# Set headers for Digital Ocean
do_headers = {'Content-Type': 'application/json',
              'Authorization': f'Bearer {do_token}'}

def draft_cert():
    mylogs.info('Drafting certificate')
    if args.days:
        cert_days = args.days
    else:
        cert_days = 90
    api_url = f'{zerossl_base}certificates?access_key={zerossl_token}'
    # Read CSR file into variable and strip out newlines
    with open(f'{fqdn}.csr', 'r') as csr:
        csr_content = csr.read().replace('\n', '')
    cert_params = {'certificate_validity_days' : cert_days,
        'certificate_domains' : fqdn,
        'certificate_csr' : csr_content}
    cert_req = requests.post(api_url, data=cert_params)
    
    resp_file = open(f'{fqdn}.resp', 'w')
    resp_file.write(cert_req.text)
    resp_file.close()
    if 'id' not in cert_req.json():
        mylogs.warning(f'Drafting certificate failed\n{cert_req.text}')
        sys.exit(3)
    else:
        cert_id=cert_req.json()['id']
        mylogs.info(f'Certificate ID is: {cert_id}')    
        cname_host=(cert_req.json()['validation']['other_methods'][f'{fqdn}']['cname_validation_p1']).replace(f'.{base_domain}','')
        mylogs.info(f'CNAME host is: {cname_host}')
        cname_value=cert_req.json()['validation']['other_methods'][f'{fqdn}']['cname_validation_p2']
        mylogs.info(f'CNAME value is: {cname_value}')
        return(cert_id,cname_host,cname_value)

def create_cname():
    mylogs.info('Creating CNAME')
    api_url = f'{do_base}domains/{base_domain}/records'

    cname_params = {'type' : 'CNAME', 'name' : f'{cname_host.lower()}',
        'data' : f'{cname_value.lower()}.', 'ttl' : 1800}
    cname_add = requests.post(api_url, headers=do_headers, json=cname_params)

    name_file = open(f'{fqdn}.name', 'w')
    name_file.write(f'{cname_host}{os.linesep}')
    name_file.write(f'{cname_value}{os.linesep}')
    name_file.write(cname_add.text)
    name_file.close()
    if 'domain_record' not in cname_add.json():
        mylogs.warning(f'Adding CNAME failed\n{cname_add.text}')
        sys.exit(4)
    else:    
        cname_id=cname_add.json()['domain_record']['id']
        mylogs.info(f'Created CNAME ID: {cname_id}')
        return(cname_id)

def test_cname():
    mylogs.info('Testing CNAME')
    cname_propagated='false'
    wait_time=20
    dns_resolver=dns.resolver.Resolver()
    while cname_propagated == 'false':
        try:
            dnslookup = dns_resolver.resolve(f'{cname_host}.{base_domain}', 'CNAME')
        except Exception as e:
            mylogs.warning(e)
            dnslookup = ''
        if len(dnslookup):
            mylogs.info(f'CNAME found: {dnslookup}')
            cname_propagated='true'
        else:
            mylogs.info(f'Waiting for {wait_time}')
            time.sleep(wait_time)
            wait_time=wait_time*2
            if wait_time > 320:
                mylogs.warning('Waited too long for DNS')
                sys.exit(5)

def validate_cert(retry):
    mylogs.info('Validating certificate')
    retries=retry+1

    api_url = f'{zerossl_base}certificates/{cert_id}/challenges?access_key={zerossl_token}'
    
    cert_vald = requests.post(api_url, data={'validation_method' : 'CNAME_CSR_HASH'})
    
    if 'id' not in cert_vald.json():
        if retries == 6:
            mylogs.warning(f'Certificate validation failed\n{cert_vald.text}')
            sys.exit(6)
        else:
            mylogs.info(f'Retry {retries} for {fqdn}' )
            time.sleep(10^retries)
            validate_cert(retries)
    
    resp_file = open(f'{fqdn}.vald', 'w')
    resp_file.write(cert_vald.text)
    resp_file.close()

def check_cert():
    mylogs.info('Checking certificate')
    api_url = f'{zerossl_base}certificates/{cert_id}?access_key={zerossl_token}'

    cert_issued='false'
    wait_time=10
    while cert_issued == 'false':
        cert_verf = requests.get(api_url)
        if cert_verf.json()['status'] == 'issued':
            mylogs.info('Cert is ready to download')
            cert_issued='true'
        else:
            mylogs.info(f'Waiting for {wait_time}')
            time.sleep(wait_time)
            wait_time=wait_time*2
            if wait_time > 320:
                mylogs.warning('Waited too long for cert to be issued')
                sys.exit(7)
    
def get_cert():
    mylogs.info('Downloading certificate')
    api_url = f'{zerossl_base}certificates/{cert_id}/download/return?access_key={zerossl_token}'

    cert = requests.get(api_url)
    cert_contents = cert.json()['certificate.crt']
    ca_contents = cert.json()['ca_bundle.crt']

    cert_file = open(f'{fqdn}.crt', 'w')
    cert_file.write(cert.json()['certificate.crt'])
    cert_file.close()

    ca_file = open(f'{fqdn}.cas', 'w')
    ca_file.write(cert.json()['ca_bundle.crt'])
    ca_file.close()

    return(cert_contents,ca_contents)

def delete_cname():
    mylogs.info('Deleting CNAME')
    api_url = f'{do_base}domains/{base_domain}/records/{cname_id}'

    requests.delete(api_url, headers=do_headers)

def generate_uc_csr(server_ip, os_user, os_pass, service, domain):
    """
    gets csr from uc server
    """

    mylogs.info('Generating CSR')

    url=f"https://{server_ip}/platformcom/api/v1/certmgr/config/csr"
    
    headers = {
        "Accept": "*/*",
        "Content-Type": "application/json"
    }

    body = {
        "service": service,
        "distribution": "this-server",
        "commonName": domain
    }

    try:
        res = requests.post(url, headers=headers, json=body, verify=False, auth=(os_user, os_pass))
        res.raise_for_status()
    except requests.exceptions.HTTPError as err:
        mylogs.warning(err)
    
    response = res.json()

    return response['csr']

def upload_uc_cert(server_ip, os_user, os_pass, service, certificate):
    """
    upload signed cert to uc server
    """
    mylogs.info('Uploading signed certificate')

    url=f"https://{server_ip}/platformcom/api/v1/certmgr/config/identity/certificates"
    
    headers = {
        "Accept": "*/*",
        "Content-Type": "application/json"
    }

    body = {
        "service": service,
        "certificates": [
                certificate
            ]
        }

    try:
        res = requests.post(url, headers=headers, json=body, verify=False, auth=(os_user, os_pass))
        res.raise_for_status()
    except requests.exceptions.HTTPError as err:
        mylogs.warning(err)
    
    response = res.json()
    return response

def upload_uc_ca(server_ip, os_user, os_pass, service, certificate):
    """
    upload signed cert to uc server
    """

    mylogs.info('Uploading CA certificate')

    url=f"https://{server_ip}/platformcom/api/v1/certmgr/config/trust/certificates"
    
    headers = {
        "Accept": "*/*",
        "Content-Type": "application/json"
    }

    body = {
        "service": [
            service
            ],
            "certificates": [
                certificate
                ],
                "description": "ZeroSSL Trust Certificate"
                }

    try:
        res = requests.post(url, headers=headers, json=body, verify=False, auth=(os_user, os_pass))
        res.raise_for_status()
    except requests.exceptions.HTTPError as err:
        mylogs.warning(err)
    
    response = res.json()
    return response

def cisco_uc_command(server_ip, os_user, os_pass,command,interaction = False):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(server_ip, username=os_user, password=os_pass)
    interact = SSHClientInteraction(ssh, timeout=90, display=True,lines_to_check=5)

    # "display=True" is just to show you what script does in real time. While in production you can set it to False
    if interaction:
        interact.expect('admin:')
        interact.send(command)
        interact.expect(['.*Paste the Certificate and Hit Enter.*','.*Include OU in CSR (yes|no)?.*'],timeout=10)
        time.sleep(5) # Wait for prompt to return
        interact.send(interaction)
        interact.send('\r\n')
        interact.expect('admin:')
    else:
        interact.expect('admin:')
        interact.send(command)
        interact.expect('admin:',timeout=30)

    return(''.join(interact.current_output_clean.splitlines(keepends=True)[1:]).strip())


if __name__ == "__main__":
    # Extract base_domain and fqdn from command line options
    base_domain=args.domain
    fqdn=args.host+'.'+base_domain
    verbose=args.verbose
    ca=args.ca
    ssh=args.ssh

    # Setup logging
    mylogs = logging.getLogger(__name__)
    mylogs.setLevel(logging.DEBUG)

    logformat = logging.Formatter("%(asctime)s:%(levelname)s:%(message)s")

    logfile = logging.FileHandler(f'{fqdn}.log')
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

    if ssh:
        create_csr = cisco_uc_command(fqdn,uc_user,uc_pass,'set csr gen tomcat','yes')

        if create_csr == 'Successfully Generated CSR  for tomcat':
            mylogs.info('CSR Generated for tomcat')
            # Get the CSR from the cisco_uc
            get_csr = cisco_uc_command(fqdn,uc_user,uc_pass,'show csr own tomcat') # Retrieve the CSR to get cert signed
    else:
        get_csr = generate_uc_csr(fqdn,uc_user,uc_pass,'tomcat',fqdn)
        
    if re.match('^(?:(?!-{3,}(?:BEGIN|END) CERTIFICATE REQUEST)[\s\S])*(-{3,}BEGIN CERTIFICATE REQUEST(?:(?!-{3,}BEGIN CERTIFICATE REQUEST)[\s\S])*?-{3,}END CERTIFICATE REQUEST-{3,})\s*$',get_csr):
        mylogs.info('CSR successfully retrieved from cisco_uc')
        # Generate a Certificate Signing Request (CSR) using OpenSSL
        mylogs.info(f'Creating CSR {fqdn}.csr')
        csr_file = open(f'{fqdn}.csr', 'w')
        csr_file.write(get_csr)
        csr_file.close()

        # Draft a certificate and extract id and cname parameters from response
        cert_details=draft_cert()
        cert_id=cert_details[0]
        cname_host=cert_details[1]
        cname_value=cert_details[2]

        # Add DNS CNAME for validation
        cname_id=create_cname()

        # Test for propogation of CNAME
        test_cname()

        # Validate certificate
        validate_cert(0)

        # Check certificate available
        check_cert()

        # Download certificates from ZeroSSL
        signed_certs = get_cert()

        if ca:
            if ssh:
                upload_ca = cisco_uc_command(fqdn,uc_user,uc_pass,'set cert import trust tomcat',signed_certs[1]) # Install CA trust chain
                mylogs.info(upload_ca)
            else:
                upload_ca = upload_uc_ca(fqdn,uc_user,uc_pass,'tomcat',signed_certs[1]) # Install CA trust chain
                mylogs.info(upload_ca)

        if ssh:
            cisco_uc_command(fqdn,uc_user,uc_pass,'set cert import own tomcat',signed_certs[0]) # Install certificate
            cisco_uc_command(fqdn,uc_user,uc_pass,'utils service restart Cisco Tomcat') # Restart Tomcat
            mylogs.info('Uploaded certificate. Restarting Cisco Tomcat.')
        else:
            # Upload signed certificate to Cisco UC
            upload_cert = upload_uc_cert(fqdn,uc_user,uc_pass,'tomcat', signed_certs[0])
            # log output
            mylogs.info(upload_cert)
            mylogs.info('Please restart tomcat:  utils service restart Cisco Tomcat')

        # Tidy up CNAME
        delete_cname()
    else:
        mylogs.warning('CSR not successfully retrieved from cisco_uc')
        sys.exit(8)