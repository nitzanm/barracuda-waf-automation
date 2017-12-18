#!/usr/bin/env python
"""
Allows you to obtain certificates from Let's Encrypt (https://letsencrypt.org/) for domains hosted on a Barracuda
Web Application Firewall.  Automatically answers Let's Encrypt's challenges using the Web Application Firewall.
"""
import argparse, subprocess, json, os, sys, base64, binascii, time, hashlib, re, copy, textwrap, logging
import pprint, tempfile, contextlib

from waf_direct_api import BarracudaWAFAPI
try:
    from urllib.request import urlopen # Python 3
except ImportError:
    from urllib2 import urlopen # Python 2


PRODUCTION_CA = "https://acme-v01.api.letsencrypt.org"
STAGING_CA = "https://acme-staging.api.letsencrypt.org"
DEFAULT_CA = STAGING_CA

LOGGER = logging
logging.basicConfig(level=logging.DEBUG)

# Let's Encrypt intermediate certificate
INTERMEDIATE_CERT = """-----BEGIN CERTIFICATE-----
MIIEkjCCA3qgAwIBAgIQCgFBQgAAAVOFc2oLheynCDANBgkqhkiG9w0BAQsFADA/
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT
DkRTVCBSb290IENBIFgzMB4XDTE2MDMxNzE2NDA0NloXDTIxMDMxNzE2NDA0Nlow
SjELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUxldCdzIEVuY3J5cHQxIzAhBgNVBAMT
GkxldCdzIEVuY3J5cHQgQXV0aG9yaXR5IFgzMIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEAnNMM8FrlLke3cl03g7NoYzDq1zUmGSXhvb418XCSL7e4S0EF
q6meNQhY7LEqxGiHC6PjdeTm86dicbp5gWAf15Gan/PQeGdxyGkOlZHP/uaZ6WA8
SMx+yk13EiSdRxta67nsHjcAHJyse6cF6s5K671B5TaYucv9bTyWaN8jKkKQDIZ0
Z8h/pZq4UmEUEz9l6YKHy9v6Dlb2honzhT+Xhq+w3Brvaw2VFn3EK6BlspkENnWA
a6xK8xuQSXgvopZPKiAlKQTGdMDQMc2PMTiVFrqoM7hD8bEfwzB/onkxEz0tNvjj
/PIzark5McWvxI0NHWQWM6r6hCm21AvA2H3DkwIDAQABo4IBfTCCAXkwEgYDVR0T
AQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwfwYIKwYBBQUHAQEEczBxMDIG
CCsGAQUFBzABhiZodHRwOi8vaXNyZy50cnVzdGlkLm9jc3AuaWRlbnRydXN0LmNv
bTA7BggrBgEFBQcwAoYvaHR0cDovL2FwcHMuaWRlbnRydXN0LmNvbS9yb290cy9k
c3Ryb290Y2F4My5wN2MwHwYDVR0jBBgwFoAUxKexpHsscfrb4UuQdf/EFWCFiRAw
VAYDVR0gBE0wSzAIBgZngQwBAgEwPwYLKwYBBAGC3xMBAQEwMDAuBggrBgEFBQcC
ARYiaHR0cDovL2Nwcy5yb290LXgxLmxldHNlbmNyeXB0Lm9yZzA8BgNVHR8ENTAz
MDGgL6AthitodHRwOi8vY3JsLmlkZW50cnVzdC5jb20vRFNUUk9PVENBWDNDUkwu
Y3JsMB0GA1UdDgQWBBSoSmpjBH3duubRObemRWXv86jsoTANBgkqhkiG9w0BAQsF
AAOCAQEA3TPXEfNjWDjdGBX7CVW+dla5cEilaUcne8IkCJLxWh9KEik3JHRRHGJo
uM2VcGfl96S8TihRzZvoroed6ti6WqEBmtzw3Wodatg+VyOeph4EYpr/1wXKtx8/
wApIvJSwtmVi4MFU5aMqrSDE6ea73Mj2tcMyo5jMd6jmeWUHK8so/joWUoHOUgwu
X4Po1QYz+3dszkDqMp4fklxBwXRsW10KXzPMTZ+sOPAveyxindmjkW8lGy+QsRlG
PfZ+G6Z6h7mjem0Y+iWlkYcV4PIWL1iwBi8saCbGS5jN2p8M+X+Q7UNKEkROb3N6
KOqkqm57TH2H3eDJAkSnh6/DNFu0Qg==
-----END CERTIFICATE----- """


class DomainVerifierFile:
    def __init__(self, acme_dir):
        self.acme_dir = acme_dir

    @contextlib.contextmanager
    def verify_domain(self, domain, token, path, file_contents):
        # make the challenge file
        wellknown_path = os.path.join(self.acme_dir, token)
        with open(wellknown_path, "w") as wellknown_file:
            wellknown_file.write(file_contents)

        yield

        os.remove(wellknown_path)


class DomainVerifierBarracudaWAF:
    def __init__(self, waf_api, service_name):
        self.waf_api = waf_api
        self.service_name = service_name

    @contextlib.contextmanager
    def verify_domain(self, domain, token, path, file_contents):
        # Create a response page that returns the verification contents
        # (Advanced->Libraries->Response Page in UI)
        response_page_name = 'LetsEncrypt-verification'
        response_page = {
            'body': file_contents,
            'headers': ['Connection:Close &lt;br&gt;Content-Type:text/plain'],
            'name': response_page_name,
            'status-code': '200 OK',
            'type': 'Other Pages'}
        self.waf_api.create_or_update_object('response-pages', response_page_name, response_page)

        # Create an Allow/Deny rule that responds with this page when the verification path is requested
        # (Websites->Allow/Deny in UI)
        acl_name = 'LetsEncrypt-verification'
        acl = {'action': 'Deny and Log',
           'comments': '',
           'deny-response': 'Response Page',
           'enable': 'On',
           'extended-match': '*',
           'extended-match-sequence': '1',
           'follow-up-action': 'None',
           'follow-up-action-time': '60',
           'host': '*',
           'name': acl_name,
           'redirect-url': '',
           'response-page': response_page_name,
           'url': path}
        self.waf_api.create_or_update_object('services/{}/url-acls'.format(self.service_name), acl_name, acl)

        yield

        self.waf_api.basic_request_json('services/{}/url-acls/{}'.format(self.service_name, acl_name), method='DELETE')
        self.waf_api.basic_request_json('response-pages/' + response_page_name, method='DELETE')


def apply_certificate_to_waf_service(waf_api, service_name, cert_name, private_key_file, certificate):
    with open(private_key_file, 'r') as f:
        private_key = f.read()

    waf_api.upload_signed_certificate(cert_name, private_key, certificate, INTERMEDIATE_CERT)

    res = waf_api.basic_request_json('services/{}/ssl-security'.format(service_name))
    res['data']['Test']['SSL Security']['certificate'] = cert_name
    waf_api.basic_request_json('services/{}/ssl-security'.format(service_name), res['data']['Test']['SSL Security'], method='PUT')

class ACMEClient:
    """
    Forked from https://github.com/diafygi/acme-tiny .
    """
    def __init__(self, account_key, domain_verifier, log=logging, CA=DEFAULT_CA):
        self.domain_verifier = domain_verifier
        self.log = log
        self.CA = CA

        self.account_registered = False
        self.account_key = account_key
        self.pub_hex, self.pub_exp = self._get_public_key_from_private_key()
        self.header = self._get_request_header()

        accountkey_json = json.dumps(self.header['jwk'], sort_keys=True, separators=(',', ':'))
        self.thumbprint = self._b64(hashlib.sha256(accountkey_json.encode('utf8')).digest())

    @staticmethod
    def _b64(b):
        """
        Helper function base64 encode for jose spec 
        """
        return base64.urlsafe_b64encode(b).decode('utf8').replace("=", "")

    def _get_public_key_from_private_key(self):
        # parse account key to get public key
        self.log.info("Parsing account key...")
        proc = subprocess.Popen(["openssl", "rsa", "-in", self.account_key, "-noout", "-text"],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate()
        if proc.returncode != 0:
            raise IOError("OpenSSL Error: {0}".format(err))
        pub_hex, pub_exp = re.search(
            r"modulus:\n\s+00:([a-f0-9\:\s]+?)\npublicExponent: ([0-9]+)",
            out.decode('utf8'), re.MULTILINE | re.DOTALL).groups()
        pub_exp = "{0:x}".format(int(pub_exp))
        pub_exp = "0{0}".format(pub_exp) if len(pub_exp) % 2 else pub_exp
        return pub_hex, pub_exp

    def _get_request_header(self):
        header = {
            "alg": "RS256",
            "jwk": {
                "e": self._b64(binascii.unhexlify(self.pub_exp.encode("utf-8"))),
                "kty": "RSA",
                "n": self._b64(binascii.unhexlify(re.sub(r"(\s|:)", "", self.pub_hex).encode("utf-8"))),
            },
        }
        return header

    # helper function make signed requests
    def _send_signed_request(self, url, payload):
        payload64 = self._b64(json.dumps(payload).encode('utf8'))
        protected = copy.deepcopy(self.header)
        protected["nonce"] = urlopen(self.CA + "/directory").headers['Replay-Nonce']
        protected64 = self._b64(json.dumps(protected).encode('utf8'))
        proc = subprocess.Popen(["openssl", "dgst", "-sha256", "-sign", self.account_key],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate("{0}.{1}".format(protected64, payload64).encode('utf8'))
        if proc.returncode != 0:
            raise IOError("OpenSSL Error: {0}".format(err))
        data = json.dumps({
            "header": self.header, "protected": protected64,
            "payload": payload64, "signature": self._b64(out),
        })
        try:
            resp = urlopen(url, data.encode('utf8'))
            return resp.getcode(), resp.read()
        except IOError as e:
            return getattr(e, "code", None), getattr(e, "read", e.__str__)()

    def get_domains_from_csr(self, csr_file):
        """
        Inspects a CSR file and returns the set of domains from it (both the CN and any alternative names).
        """
        self.log.info("Parsing CSR...")
        proc = subprocess.Popen(["openssl", "req", "-in", csr_file, "-noout", "-text"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate()
        if proc.returncode != 0:
            raise IOError("Error loading {0}: {1}".format(csr, err))
        domains = set([])
        common_name = re.search(r"Subject:.*? CN\s?=\s?([^\s,;/]+)", out.decode('utf8'))
        if common_name is not None:
            domains.add(common_name.group(1))
        subject_alt_names = re.search(r"X509v3 Subject Alternative Name: \n +([^\n]+)\n", out.decode('utf8'),
                                      re.MULTILINE | re.DOTALL)
        if subject_alt_names is not None:
            for san in subject_alt_names.group(1).split(", "):
                if san.startswith("DNS:"):
                    domains.add(san[4:])

        return domains

    def register_account(self):
        if self.account_registered:
            return

        self.log.info("Registering account...")
        code, result = self._send_signed_request(self.CA + "/acme/new-reg", {
            "resource": "new-reg",
            "agreement": json.loads(urlopen(self.CA + "/directory").read().decode('utf8'))['meta']['terms-of-service'],
        })
        if code == 201:
            self.log.info("Registered!")
        elif code == 409:
            self.log.info("Already registered!")
        else:
            raise ValueError("Error registering: {0} {1}".format(code, result))
        self.account_registered = True

    def verify_domain(self, domain):
        self.log.info("Verifying {0}...".format(domain))

        # get new challenge
        code, result = self._send_signed_request(self.CA + "/acme/new-authz", {
            "resource": "new-authz",
            "identifier": {"type": "dns", "value": domain},
        })
        if code != 201:
            raise ValueError("Error requesting challenges: {0} {1}".format(code, result))
        result_json = json.loads(result.decode('utf8'))

        # Have we already completed this challenge?
        #if result_json['status'] == 'valid':
        #    return

        challenge = next(c for c in result_json['challenges'] if c['type'] == "http-01")
        token = re.sub(r"[^A-Za-z0-9_\-]", "_", challenge['token'])
        keyauthorization = "{0}.{1}".format(token, self.thumbprint)

        path = "/.well-known/acme-challenge/{1}".format(domain, token)
        with self.domain_verifier.verify_domain(domain, token, path, keyauthorization):
            # check that the file is in place
            wellknown_url = "http://{}/{}".format(domain, path)
            try:
                resp = urlopen(wellknown_url)
                resp_data = resp.read().decode('utf8').strip()
                assert resp_data == keyauthorization
            except (IOError, AssertionError):
                raise ValueError("Couldn't download {}: {}".format(
                    wellknown_url, sys.exc_info()))

            # notify challenge are met
            code, result = self._send_signed_request(challenge['uri'], {
                "resource": "challenge",
                "keyAuthorization": keyauthorization,
            })
            if code != 202:
                raise ValueError("Error triggering challenge: {0} {1}".format(code, result))

            # wait for challenge to be verified
            while True:
                try:
                    resp = urlopen(challenge['uri'])
                    challenge_status = json.loads(resp.read().decode('utf8'))
                except IOError as e:
                    raise ValueError("Error checking challenge: {0} {1}".format(
                        e.code, json.loads(e.read().decode('utf8'))))
                if challenge_status['status'] == "pending":
                    time.sleep(2)
                elif challenge_status['status'] == "valid":
                    self.log.info("{0} verified!".format(domain))
                    break
                else:
                    raise ValueError("{0} challenge did not pass: {1}".format(
                        domain, challenge_status))

    def sign_csr(self, csr_file):
        self.log.info("Signing certificate...")
        proc = subprocess.Popen(["openssl", "req", "-in", csr_file, "-outform", "DER"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        csr_der, err = proc.communicate()
        code, result = self._send_signed_request(self.CA + "/acme/new-cert", {
            "resource": "new-cert",
            "csr": self._b64(csr_der),
        })
        if code != 201:
            raise ValueError("Error signing certificate: {0} {1}".format(code, result))

        # return signed certificate!
        self.log.info("Certificate signed!")
        return """-----BEGIN CERTIFICATE-----\n{0}\n-----END CERTIFICATE-----\n""".format(
            "\n".join(textwrap.wrap(base64.b64encode(result).decode('utf8'), 64)))

    def _tempfile(self, contents):
        tmp_file_handle, tmp_filename = tempfile.mkstemp(text=True)
        tmp_file = os.fdopen(tmp_file_handle, 'w')
        tmp_file.write(contents)
        tmp_file.close()
        return tmp_filename

    def get_certificate_for_domains(self, domains, private_key_file, csr_file, cert_file):
        assert len(domains) > 0

        # Create temporary OpenSSL config file
        with open('openssl-csr-san-template.cnf', 'r') as f:
            config_template = f.read()
        config = config_template.format(domains[0], '#' if len(domains) == 1 else '',
                                        '\n'.join('DNS.{}={}'.format(i + 1, d) for i, d in enumerate(domains[1:])))
        config_filename = self._tempfile(config)

        # Create private key
        if not os.path.exists(private_key_file):
            self.log.info("Creating private key...")
            proc = subprocess.Popen(["openssl", "genrsa", "4096"],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            key, err = proc.communicate()
            if proc.returncode != 0:
                raise Exception("OpenSSL returned error while creating private key: {}".format(err))
            with open(private_key_file, 'w') as f:
                f.write(key.decode('latin-1'))

        # Create CSR
        proc = subprocess.Popen(
            "openssl req -new -batch -sha256 -key {private_key_file} -out {csr_file} -config {config_filename}".format(
                private_key_file=private_key_file, csr_file=csr_file, config_filename=config_filename),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate()
        if proc.returncode != 0:
            raise IOError("OpenSSL return error while creating CSR: {0}".format(err))

        # Delete temp config
        os.unlink(config_filename)

        # Get certificate
        cert = self.get_certificate_from_csr(csr_file)
        with open(cert_file, 'w') as f:
            f.write(cert)
            f.write(INTERMEDIATE_CERT)
            f.close()

        return cert


    def get_certificate_from_csr(self, csr_file):
        domains = self.get_domains_from_csr(csr_file)
        self.register_account()

        for domain in domains:
            self.verify_domain(domain)

        return self.sign_csr(csr_file)

    @staticmethod
    def get_serial_number_from_certificate(cert_file):
        proc = subprocess.Popen(["openssl", "x509", "-in", cert_file, "-noout", "-text"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate()
        if proc.returncode != 0:
            raise IOError("Error loading {0}: {1}".format(cert_file, err))
        serial_number = re.search(r"Serial Number:\s+([0-9a-fA-F:]+)\s+Signature Algorithm", out.decode('utf-8'))
        if not serial_number:
            raise IOError("Canot parse serial number from {}".format(cert_file))
        return serial_number.group(1).replace(':', '')


def main(argv):
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("""\
            This script automates the process of getting a signed TLS certificate from
            Let's Encrypt using the ACME protocol. It will need to be run on your server
            and have access to your private account key, so PLEASE READ THROUGH IT! It's
            only ~200 lines, so it won't take long.

            ===Example Usage===
            python acme_tiny.py --account-key ./account.key --csr ./domain.csr --acme-dir /usr/share/nginx/html/.well-known/acme-challenge/ > signed.crt
            ===================

            ===Example Crontab Renewal (once per month)===
            0 0 1 * * python /path/to/acme_tiny.py --account-key /path/to/account.key --csr /path/to/domain.csr --acme-dir /usr/share/nginx/html/.well-known/acme-challenge/ > /path/to/signed.crt 2>> /var/log/acme_tiny.log
            ==============================================
            """)
    )
    parser.add_argument("-k", "--account-key", required=True, help="Path to your Let's Encrypt account private key")
    parser.add_argument("-w", "--waf-netloc", required=True, help="WAF netloc, in the format <host>[:<port>]")
    parser.add_argument("-S", "--waf-secure", action='store_true', default=False, help="Connect to WAF using HTTPS")
    parser.add_argument("-u", "--waf-user", required=True, help="Login username to your WAF")
    parser.add_argument("-p", "--waf-password", required=True, help="Login password to your WAF")
    parser.add_argument("-s", "--waf-service", required=True, help="Service on your WAF to verify with")
    parser.add_argument("-d", "--domains", nargs="+", required=True, help="List of domain(s) to verify")
    parser.add_argument("--private-key-file", default="domain.key", help="File in which to place/read private key for cert")
    parser.add_argument("--csr-file", default="domain.csr", help="File in which to place CSR")
    parser.add_argument("--cert-file", default="domain.crt", help="File in which to place signed certificate")
    parser.add_argument("--waf-ssl-service", help="Service on WAF to upload resulting SSL certificate to")

    parser.add_argument("--quiet", action="store_const", const=logging.ERROR, help="Suppress output except for errors")
    parser.add_argument("--ca", default=DEFAULT_CA, help="Certificate authority, default is Let's Encrypt")

    args = parser.parse_args(argv)
    logging.getLogger().setLevel(args.quiet or logging.getLogger().level)

    waf_api = BarracudaWAFAPI(args.waf_netloc, args.waf_user, args.waf_password, args.waf_secure)
    verifier = DomainVerifierBarracudaWAF(waf_api, args.waf_service)

    client = ACMEClient(args.account_key, verifier, logging, args.ca)
    certificate = client.get_certificate_for_domains(args.domains, args.private_key_file, args.csr_file, args.cert_file)

    if args.waf_ssl_service:
        serial_number = client.get_serial_number_from_certificate(args.cert_file)
        apply_certificate_to_waf_service(waf_api, args.waf_ssl_service, serial_number, args.private_key_file, certificate)


if __name__ == "__main__": # pragma: no cover
    main(sys.argv[1:])
