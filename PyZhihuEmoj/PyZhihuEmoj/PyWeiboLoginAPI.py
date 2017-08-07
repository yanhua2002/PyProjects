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

    def get_zhihu_token(self):
        zhihu_home=self.session.get("http://www.zhihu.com")
        self.csrf_string=zhihu_home.cookies["_xsrf"]
        redirect_to_sina_res=self.session.get("https://www.zhihu.com/oauth/redirect/login/sina?next=/oauth/account_callback&from=%2F")
        logging.debug("redirect to sina response: %s",redirect_to_sina_res.status_code)
        return

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
        login_referer="https://api.weibo.com/oauth2/authorize?scope=email&state="+self.csrf_string+"redirect_uri=http%3A%2F%2Fwww.zhihu.com%2Foauth%2Fcallback%2Fsina&response_type=code&client_id=3063806388"
        try:
            response=self.session.get("https://login.sina.com.cn/sso/prelogin.php",
                                      params=params,
                                      headers={"Referer":login_referer})
            logging.debug("response.text: %s",response.text)
            prelogin_data=json.loads(re.search(r"\((?P<data>.*)\)", response.text).group("data"))
        except Exception as excep:
            prelogin_data={}
            logging.error("WeiboLogin get_prelogin_data error: %s",excep)

        logging.debug("WeiboLogin get_prelogin_data: %s",prelogin_data)
        return prelogin_data

    def encode_password(self, servertime, nonce, pubkey):
        message=(str(servertime)+"\t"+str(nonce)+"\n"+str(self.pass_word)).encode("utf-8")
        public_key=rsa.PublicKey(int(pubkey,16),int("10001",16))
        password=rsa.encrypt(message,public_key)
        password=binascii.b2a_hex(password)
        return password.decode()

    def login(self, user_name, pass_word):

        self.user_name=user_name
        self.pass_word=pass_word

        self.get_zhihu_token()

        login_referer="https://api.weibo.com/oauth2/authorize?scope=email&state="+self.csrf_string+"redirect_uri=http%3A%2F%2Fwww.zhihu.com%2Foauth%2Fcallback%2Fsina&response_type=code&client_id=3063806388"

        s_user_name=self.encode_username()
        logging.debug("s_user_name: %s",s_user_name)
        prelogin_data=self.get_prelogin_data(su_value=s_user_name)
        s_pass_word=self.encode_password(prelogin_data["servertime"],prelogin_data["nonce"],prelogin_data["pubkey"])
        logging.debug("s_pass_word: %s",s_pass_word)

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
            "su":s_user_name,
            "service":"miniblog",
            "servertime":prelogin_data["servertime"],
            "nonce":prelogin_data["nonce"],
            "pwencode":"rsa2",
            "rsakv":prelogin_data["rsakv"],
            "sp":s_pass_word,
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

        login_url="https://login.sina.com.cn/sso/login.php?client=ssologin.js(v1.4.18)&_=%d&openapilogin=qrcode" % int(time.time())
        login_res_data=self.session.post(login_url,
                                         data=post_data,
                                         headers={"Referer":login_referer}).json()
        logging.debug("login_res_data: %s",login_res_data)
        if login_res_data["retcode"]=="0":
            auth1_post_data={
                "action":"login",
                "display":"default",
                "withOfficalFlag":"0",
                "quick_auth":"null",
                "withOfficalAccount":"null",
                "scope":"email",
                "ticket":login_res_data["ticket"],
                "isLoginSina":"",
                "response_type":"code",
                "regCallback":"https%3A%2F%2Fapi.weibo.com%2F2%2Foauth2%2Fauthorize%3Fclient_id%3D3063806388%26response_type%3Dcode%26display%3Ddefault%26redirect_uri%3Dhttp%253A%252F%252Fwww.zhihu.com%252Foauth%252Fcallback%252Fsina%26from%3D%26with_cookie%3D",
                "redirect_uri":"http://www.zhihu.com/oauth/callback/sina",
                "client_id":"3063806388",
                "appkey62":"4WfYdm",
                "state":self.csrf_string,
                "verifyToken":"null",
                "from":"",
                "switchLogin":"null",
                "userId":"",
                "passwd":""}
            auth1_res=self.session.post("https://api.weibo.com/oauth2/authorize",
                                        data=auth1_post_data,
                                        headers={"Referer":login_referer})
            logging.debug("auth1_res.status_code: %s",auth1_res.status_code)
            """auth2_form=re.search(r"<form name=\"authZForm\".*?\/form>",auth1_res.text)"""
            """auth2_form=re.findall(r"<input type=\"hidden\".*?\/>",auth1_res.text)"""
            auth2_post_data={}
            key_value_pattern=re.compile(r"name=\"(?P<name>.*?)\".*?value=\"(?P<value>.*?)\"")
            for m in re.finditer(r"<input type=\"hidden\".*?\/>",auth1_res.text):
                form_item=key_value_pattern.search(m.group(0))
                auth2_post_data[form_item.group("name")]=form_item.group("value")
            logging.debug("auth2_post_data: %s",auth2_post_data)
            auth2_res=self.session.post("https://api.weibo.com/oauth2/authorize",
                                        data=auth2_post_data,
                                        headers={"Referer":"https://api.weibo.com/oauth2/authorize",
                                                 "Origin":"https://api.weibo.com",
                                                 "Host":"api.weibo.com",
                                                 "Upgrade-Insecure-Requests":"1",
                                                 "Content-Type":"application/x-www-form-urlencoded"})
            logging.debug("auth2_res.status_code: %s",auth2_res.status_code)
            if auth2_res.status_code==502:
                redirecturl=auth2_res.history[0].headers["Location"].replace("http:","https:")
                redirect_res=self.session.get(redirecturl,
                                              headers={"Host":"www.zhihu.com",
                                                       "Upgrade-Insesure-Requests":"1"})
                logging.debug("redirect_res.text: %s",redirect_res.text)
                zhihu_home_loggedin=self.session.get("https://www.zhihu.com",
                                                     headers={"Host":"www.zhihu.com",
                                                              "Referer":redirecturl,})
                logging.debug("zhihu homepage loggedin: %s",zhihu_home_loggedin.status_code)
        return

weibo=PyWeiboLoginAPI()
weibo.login("13793288171","husu0301")