# Cisco UC certificate generation using ZeroSSL and Digital Ocean

> Python project that will generate a CSR on UC platform, request a certificate from ZeroSSL, verify domain via Digital Ocean, and install CA and signed certificate on server.

> https://developer.cisco.com/docs/certificate-management/#!introduction/introduction
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
DO_KEY=
ZEROSSL_KEY=
UC_IP=
UC_USER=
UC_PASS=
```
Run python scripts with correct flags
```
python3 get-cert.py --host cucm --domain cisco.com

optional arguments:
  -h, --help       show this help message and exit
  -v, --verbose    Enable verbose output
  -ca              Install CA certificate
  --ssh             Install certificate via SSH instead of API.
  --days DAYS      Certificate Validity Days, default 90
```

## Blog

[Medium](https://medium.com/automate-builders)

## Giving Back

If you would like to support my work and the time I put in creating the code, you can click the image below to get me a coffee. I would really appreciate it (but is not required).

[![Buy Me A Coffee](https://www.buymeacoffee.com/assets/img/custom_images/black_img.png)](https://www.buymeacoffee.com/automatebldrs)

-Jeremy Worden
