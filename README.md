# Cisco UC Certification Generator

Python project that will generate a CSR, request a certificate, verify domain and install CA and signed certificate on a Cisco VOS server.

## Built Using

### SSL Certificate Providers
- ZeroSSL - [ZeroSSL API](https://zerossl.com/documentation/api/)
- Let's Encrypt - [Let's Encrypt API](https://letsencrypt.org/docs/)

### DNS Verification (for ZeroSSL)
- MXToolBox - [MXTOOLBOX API](https://mxtoolbox.com/user/api)

### DNS Providers
- Cloudflare - [Cloudflare API](https://developers.cloudflare.com/api)
- DigitalOcean - [DigitalOcean API](https://www.digitalocean.com/docs/apis-clients/api/)
- AWS Route53 - [AWS Route53 API](https://docs.aws.amazon.com/Route53/latest/APIReference/Welcome.html)
- Azure DNS - [Azure DNS API](https://learn.microsoft.com/en-us/azure/dns/)
- Google Cloud DNS - [Google Cloud DNS API](https://cloud.google.com/dns/docs/apis)

Note: Currently have only tested Cloudflare and DigitalOcean. The other DNS providers are provided based on documentation, please open an issue if these do not working for you.

### Certificate Management
- Cisco UC - [Cisco UC API](https://developer.cisco.com/docs/certificate-management/#!introduction/introduction)

> Note: The Certification Management API supports CUCM, IM&P, CUC, and CER products with version 14 and later. Earlier versions will need to use SSH to install certificates.

> Need to restart services after install. This can be done via SSH or AXL. 'utils service restart Cisco Tomcat'

## Usage

Create python environment

```bash
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
```

Create ENV file

```bash
touch .env
```

Add variables to ENV file. Only add the variables for the DNS provider you plan to use:

```bash
# Required Variables
UC_USER=
UC_PASS=

# SSL Provider Keys (choose one)

# For Let's Encrypt
LETSENCRYPT_EMAIL=

# For ZeroSSL
ZEROSSL_KEY=
MXTOOLBOX_KEY=

# DNS Provider Variables (choose one section)

# For Cloudflare
CF_KEY=
CF_ZONE=
# Optional DNS Servers if using Let's Encrypt
LETSENCRYPT_DNS_1="1.1.1.1"
LETSENCRYPT_DNS_2="1.0.0.1"

# For DigitalOcean
DO_KEY=
# Optional DNS Servers if using Let's Encrypt
LETSENCRYPT_DNS_1="67.207.67.2"
LETSENCRYPT_DNS_2="67.207.67.3"

# For AWS Route53
AWS_ACCESS_KEY=
AWS_SECRET_KEY=
AWS_ZONE_ID=
# Optional DNS Servers if using Let's Encrypt
LETSENCRYPT_DNS_1="8.8.8.8"
LETSENCRYPT_DNS_2="8.8.4.4"

# For Azure DNS
AZURE_SUBSCRIPTION_ID=
AZURE_RESOURCE_GROUP=
AZURE_ZONE_NAME=
# Optional DNS Servers if using Let's Encrypt
LETSENCRYPT_DNS_1="168.63.129.16"
LETSENCRYPT_DNS_2="208.67.220.220"

# For Google Cloud DNS
GOOGLE_PROJECT_ID=
GOOGLE_ZONE_NAME=
# Optional DNS Servers if using Let's Encrypt
LETSENCRYPT_DNS_1="8.8.8.8"
LETSENCRYPT_DNS_2="8.8.4.4"
```

Run python scripts with correct flags
```bash
python3 get-cert.py --host cucm --domain cisco.com [-h] [-v] [-ca] [--ssh] [--days DAYS] [--dnsprovider PROVIDER] [--sslprovider PROVIDER]

optional arguments:
  -h, --help       show this help message and exit
  -v, --verbose    Enable verbose output
  -ca              Install Intermediate Certificate
  --ssh            Install certificate via SSH instead of API.
  --days           Certificate Validity Days. Defaults to 90 days. Options are 90 or 365. Note: Let's Encrypt only supports 90 days.
  --dnsprovider    DNS Provider. Defaults to cloudflare. Options are cloudflare, digitalocean, route53, azure, or google.
  --sslprovider    SSL Provider. Defaults to letsencrypt. Options are zerossl or letsencrypt.
```

## Restart Services

Provided is a script to restart services via ssh. This is useful if you are using the API to install the certificate.

```bash
python3 helpers/sshRestartCiscoTomcat.py -H cucm.cisco.com -u administrator -p ciscopsdt
```

## Troubleshooting

If you run into issues, please check the following:
1. **Check Environment Variables**: Ensure all required environment variables are set correctly in the `.env` file.
2. **Verbose Mode**: Run the script with the `-v` or `--verbose` flag to get detailed output for debugging.
3. **DNS Propagation**: If using DNS verification, ensure that DNS records have propagated before running the script.
4. **Firewall Rules**: Ensure that the Cisco UC server is accessible from the machine running the script, and that any necessary firewall rules are in place.
5. **Certificate Authority Limits**: Be aware of any rate limits imposed by the SSL provider (e.g., Let's Encrypt has limits on the number of certificates issued per domain per week). 

If you see the following error, it is likely due to the CA certificate not being installed on the Cisco UC server:

```
ERROR:Failed to upload certificate: 400 Client Error:  for url: https://localhost/platformcom/api/v1/certmgr/config/identity/certificates
```

If you see this error, you will need to change the DNS servers in your `.env` file to public DNS servers. This is because the SSL validation servers are unable to reach your server's DNS records:

```
ERROR:An error occurred: All nameservers failed to answer the query _acme-challenge.cucm01-pub.automate.builders. IN TXT: Server Do53:172.64.52.210@53 answered REFUSED; Server Do53:172.64.53.21@53 answered REFUSED
```


## Blog

Like content like this? Check out my [Medium](https://medium.com/automate-builders) blog for more projects.

## Giving Back

If you would like to support my work and the time I put in creating the code, you can click the image below to get me a coffee. I would really appreciate it (but is not required).

[![Buy Me A Coffee](https://www.buymeacoffee.com/assets/img/custom_images/black_img.png)](https://www.buymeacoffee.com/automatebldrs)

-Jeremy Worden