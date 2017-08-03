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
        self.prelogin_data=None

        post_data={
            "entry":"openapi",
            "gateway":"1",
            "from":"",
            "savestate":"0",
            "useticket":"1",
            "pagerefer":"https://www.zhihu.com/",
            "ct":"1800",
            "s":"1",
            "vsnf":"1",
            "vsnval":"",
            "door":"",
            "appkey":"4WfYdm",
            "su":self.user_name,
            "service":"miniblog",
            "servertime":self.prelogin_data["servertime"],
            "nonce":self.prelogin_data["nonce"],
            "pwencode":"rsa2",
            "rsakv":self.prelogin_data["rsakv"],
            "sp":self.pass_word,
            "sr":"1920*1080",
            "encoding":"UTF-8",
            "cdult":"2",
            "domain":"weibo.com",
            "prelt":"40",
            "returntype":"TEXT"}

        if prelogin_data["showpin"]==1:
            qrurl="http://login.sina.com.cn/cgi/pin.php?r=%d&s=0&p=%s" % (int(time.time()),prelogin_data["pcid"])
            with open("captcha.jpeg","wb") as file_out:
                file_out.write(self.session.get(qrurl).content)
            code=input("Please input the qr code:")
            post_data["pcid"]=prelogin_data["pcid"]
            post_data["door"]=code


        return