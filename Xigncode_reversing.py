"""
Custom proxy to decrypt Xigncode request & response on the fly.
"""

from __future__ import with_statement

import hashlib
import base64
import copy
import pickle
from mitmproxy import flow, controller
from mitmproxy.proxy import ProxyServer, ProxyConfig
from Crypto.Cipher import AES

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)

class AESUtil:
    def __init__(self, key):
        self.key = key
        self.iv = '\x00' * 16

    def encrypt(self, raw):
        raw = pad(raw)
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        return base64.b64encode(cipher.encrypt(raw))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        return cipher.decrypt(enc)


def decr(key, data):
    encryptor = AESUtil(key)
    plain = encryptor.decrypt(data)
    return plain

def encr(key, data):
    encryptor = AESUtil(key)
    ciphertext = encryptor.encrypt(data)
    return ciphertext

def md5(ts):
    m = hashlib.md5()
    m.update(ts)
    return m.hexdigest()

q = []
class CustomProxy(flow.FlowMaster):
    """
    Custom proxy hooks for request & response
    """
    def run(self):
        try:
            flow.FlowMaster.run(self)
        except KeyboardInterrupt:
            self.shutdown()

    def handle_request(self, f):
        f = flow.FlowMaster.handle_request(self, f)
        if f:
            f.reply()

        if f.request.path == "/gateway.php":
            q.append(f.id)
            header = f.request.headers
            req_ts = header['REQ-TIMESTAMP']
            req_auth = header['REQ-AUTHKEY']
            content = f.request.content
            key = md5(req_ts)[0:16]
            plain = decr(key, content)
            print "Decrypted request body",  plain

        return f

    def handle_response(self, f):
        f = flow.FlowMaster.handle_response(self, f)
        if f:
            f.reply()

        if f.id in q:
            q.remove(f.id)
            header = f.response.headers
            req_ts = header['REQ-TIMESTAMP']
            req_auth = header['REQ-AUTHKEY']
            content = f.response.content
            key = md5(req_ts)[0:16]
            plain = decr(key, content)
            print "Decrypted response body",  plain
        return f


if __name__ == '__main__':
    PROXY_HOST = os.environ.get("ROXY_HOST", "0.0.0.0")
    PROXY_PORT = os.environ.get("ROXY_PORT", 8080)
    BASE_DIR = os.path.dirname(os.path.realpath(__file__))
    PROXY_CA_DIR = os.path.join(BASE_DIR, 'ca')

    proxy_config = ProxyConfig(
        host=PROXY_HOST,
        port=PROXY_PORT,
        cadir=PROXY_CA_DIR
    )
    state = flow.State()
    server = ProxyServer(proxy_config)
    m = CustomProxy(server, state)
    m.run()
