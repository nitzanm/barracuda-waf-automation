#!/usr/bin/env python
"""
Allows you to obtain certificates from Let's Encrypt (https://letsencrypt.org/) for domains hosted on a Barracuda
Web Application Firewall.  Automatically answers Let's Encrypt's challenges using the Web Application Firewall.
"""
import argparse, subprocess, json, os, sys, base64, binascii, time, hashlib, re, copy, textwrap, logging
import pprint, tempfile, contextlib
from urllib.request import urlopen

from utils.waf_direct_api import BarracudaWAFAPI
from utils.waf_acme import DomainVerifierBarracudaWAF, apply_certificate_to_waf_service
from utils.acme_client import ACMEClient, INTERMEDIATE_CERT, DEFAULT_CA

LOGGER = logging
logging.basicConfig(level=logging.DEBUG)

def main(argv):
    parser = argparse.ArgumentParser()
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
        apply_certificate_to_waf_service(waf_api, args.waf_ssl_service, serial_number, args.private_key_file, certificate, INTERMEDIATE_CERT)


if __name__ == "__main__": # pragma: no cover
    main(sys.argv[1:])
