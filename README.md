# Cisco UC Certification Generator

> Python project that will generate a CSR, request a certificate, verify domain and install CA and signed certificate on server.

Built using:
- ZeroSSL (SSL Certificate) - [ZeroSSL API](https://zerossl.com/documentation/api/)
- Let's Encrypt (SSL Certificate) - [Let's Encrypt API](https://letsencrypt.org/docs/)
- MXToolBox (DNS Verification) - [MXTOOLBOX API](https://mxtoolbox.com/user/api)
- DigitalOcean (DNS Provider) - [DigitalOcean API](https://www.digitalocean.com/docs/apis-clients/api/)
- Cloudflare  (DNS Provider) - [Cloudflare API](https://developers.cloudflare.com/api)
- Cisco UC (Certificate Management) - [Cisco UC API](https://developer.cisco.com/docs/certificate-management/#!introduction/introduction)

> Note: The Certification Management API supports CUCM, IM&P, CUC, and CER products with version 14 and later.

> Need to restart services after install. This can be done via SSH or AXL. 'utils service restart Cisco Tomcat'

## Usage

Create python enviromemnt

```
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt

```
Create ENV file

```
touch .env
```
Add variables to ENV file

```
CF_KEY=
CF_ZONE=
DO_KEY=
ZEROSSL_KEY=
MXTOOLBOX_KEY=
UC_USER=
UC_PASS=
LETSENCRYPT_EMAIL=
```
Run python scripts with correct flags
```
python3 get-cert.py --host cucm --domain cisco.com [-h] [-v] [-ca] [--ssh] [--days DAYS] [--dnsprovider PROVIDER] [--sslprovider PROVIDER]

optional arguments:
  -h, --help       show this help message and exit
  -v, --verbose    Enable verbose output
  -ca              Install Intermediate Certificate
  --ssh            Install certificate via SSH instead of API.
  --days           Certificate Validity Days. Defaults to 90 days. Options are 90 or 365. Note: Let's Encrypt only supports 90 days.
  --dnsprovider    DNS Provider. Defaults to cloudflare. Options are digitalocean or cloudflare.
  --sslprovider    SSL Provider. Defaults to letsencrypt. Options are zerossl or letsencrypt.
```

## Blog

Like content like this? Check out my [Medium](https://medium.com/automate-builders) blog for more projects.

## Giving Back

If you would like to support my work and the time I put in creating the code, you can click the image below to get me a coffee. I would really appreciate it (but is not required).

[![Buy Me A Coffee](https://www.buymeacoffee.com/assets/img/custom_images/black_img.png)](https://www.buymeacoffee.com/automatebldrs)

-Jeremy Worden
