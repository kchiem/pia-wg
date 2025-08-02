import requests
import json
from requests_toolbelt.adapters import host_header_ssl
import urllib3
import subprocess
import urllib.parse
import ssl
import warnings
from sys import version_info


# fix for Python 3.13 enforcing X509 strict verification, based on
# https://stackoverflow.com/questions/79358216/python-v3-13-has-broken-email-delivery-due-to-an-ssl-change
if version_info[0] == 3 and version_info[1] >= 13:
    print("Attempting X509_STRICT workaround for ca.rsa.4096.crt")
    try:
        original_urllib3_request_context = requests.adapters._urllib3_request_context

        def patched_urllib3_request_context(*args, **kwargs):
            host_params, pool_kwargs = original_urllib3_request_context(*args, **kwargs)
            if 'ca_certs' in pool_kwargs and pool_kwargs['ca_certs'] == 'ca.rsa.4096.crt':
                warnings.warn("Disabling VERIFY_X509_STRICT and VERIFY_X509_PARTIAL_CHAIN")
                context = urllib3.util.create_urllib3_context()
                context.verify_flags = context.verify_flags & ~ssl.VERIFY_X509_STRICT
                pool_kwargs["ssl_context"] = context

            return host_params, pool_kwargs

        requests.adapters._urllib3_request_context = patched_urllib3_request_context
    except:
        pass



class piawg:
    def __init__(self):
        self.server_list = {}
        self.get_server_list()
        self.region = None
        self.token = None
        self.publickey = None
        self.privatekey = None
        self.connection = None

    def get_server_list(self):
        r = requests.get('https://serverlist.piaservers.net/vpninfo/servers/v4')
        # Only process first line of response, there's some base64 data at the end we're ignoring
        data = json.loads(r.text.splitlines()[0])
        for server in data['regions']:
            self.server_list[server['name']] = server

    def set_region(self, region_name):
        self.region = region_name

    def get_token(self, username, password):
        # Get common name and IP address for metadata endpoint in region
        meta_cn = self.server_list[self.region]['servers']['meta'][0]['cn']
        meta_ip = self.server_list[self.region]['servers']['meta'][0]['ip']

        # Some tricks to verify PIA certificate, even though we're sending requests to an IP and not a proper domain
        # https://toolbelt.readthedocs.io/en/latest/adapters.html#requests_toolbelt.adapters.host_header_ssl.HostHeaderSSLAdapter
        s = requests.Session()
        s.mount('https://', host_header_ssl.HostHeaderSSLAdapter())
        s.verify = 'ca.rsa.4096.crt'

        r = s.get("https://{}/authv3/generateToken".format(meta_ip), headers={"Host": meta_cn},
                  auth=(username, password))
        data = r.json()
        if r.status_code == 200 and data['status'] == 'OK':
            self.token = data['token']
            return True
        else:
            return False

    def generate_keys(self):
        self.privatekey = subprocess.run(['wg', 'genkey'], stdout=subprocess.PIPE, encoding="utf-8").stdout.strip()
        self.publickey = subprocess.run(['wg', 'pubkey'], input=self.privatekey, stdout=subprocess.PIPE,
                                        encoding="utf-8").stdout.strip()

    def addkey(self):
        # Get common name and IP address for wireguard endpoint in region
        cn = self.server_list[self.region]['servers']['wg'][0]['cn']
        ip = self.server_list[self.region]['servers']['wg'][0]['ip']

        s = requests.Session()
        s.mount('https://', host_header_ssl.HostHeaderSSLAdapter())
        s.verify = 'ca.rsa.4096.crt'

        r = s.get("https://{}:1337/addKey?pt={}&pubkey={}".format(ip, urllib.parse.quote(self.token),
                                                                  urllib.parse.quote(self.publickey)), headers={"Host": cn})
        if r.status_code == 200 and r.json()['status'] == 'OK':
            self.connection = r.json()
            return True, r.content
        else:
            return False, r.content
