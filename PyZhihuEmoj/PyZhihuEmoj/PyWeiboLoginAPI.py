import re
import requests
import rsa
import base64
import binascii
import logging
import json
import time
import urllib.parse

class PyWeiboLoginAPI(object):
    """login with weibo ID helper class"""

    def __init__(self):
        self.user_name=None
        self.pass_word=None
        self.csrf_string=None

        self.session=requests.Session()
        self.session.headers.update({"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36"})

    def encode_username(self):
        """ encode user name """

        username_quote=urllib.parse.quote_plus(self.user_name)
        username_base64=base64.b64encode(username_quote.encode("utf-8"))
        return username_base64.decode("utf-8")

    def get_prelogin_data(self, su_value):
        params={
            "entry":"openapi",
            "callback":"sinaSSOController.preloginCallBack",
            "su":su_value,
            "rsakt":"mod",
            "checkpin":"1",
            "client":"ssologin.js(v1.4.18)",
            "_":int(time.time()*1000)}
        try:
            response=self.session.get("https://login.sina.com.cn/sso/prelogin.php",params=params)
            prelogin_data=json.loads(re.search(r"\((?P<data>.*)\)", response.text).group("data"))
        except Exception as excep:
            prelogin_data={}
            logging.error("WeiboLogin get_prelogin_data error: %s",excep)

        logging.debug("WeiboLogin get_prelogin_data: %s",prelogin_data)
        return prelogin_data

    def encode_password(pass_word, servertime, nonce, pubkey):
        message=(str(servertime)+"\t"+str(nonce)+"\n"+str(pass_word)).encode("utf-8")
        public_key=rsa.PublicKey(int(pubkey,16),int("10001",16))
        password=rsa.encrypt(message,public_key)
        password=binascii.b2a_hex(password)
        return password.decode()

    def login(self, user_name, pass_word):

        self.user_name=user_name
        self.pass_word=pass_word

        return