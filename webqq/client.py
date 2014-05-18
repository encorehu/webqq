# -*- coding: utf-8 -*-

import json
import random

from webclient import WebBrowser

from protocol import (WEBQQ_APPID,
    get_timestamp,
    get_clientid,
    get_password,
    )




class WebQQException(Exception):
    pass

class WebQQClient(WebBrowser):
    def __init__(self, *args, **kwargs):
        super(WebQQClient, self).__init__()
        self.handle_count = 0
        self.ptwebqq    = ''
        self.set_runflag(False)

    def need_login_ptlogin2(self):
        # 看看 这个机器人还需不需要再次登录http://ptlogin2.qq.com/login
        # ptwebqq 的值是未注销之前的值, 如果有值, 说明cookie或者内存中有这个值, 机器人还处于未注销的状态, 就不需要再次登录网站了
        if self.cookiejar == None:
            return True
        else:
            for index,cookie in enumerate(self.cookiejar):
                #print index,":",cookie
                if cookie.name == 'ptwebqq':
                    self.ptwebqq = cookie.value

                if cookie.name == 'skey':
                    self.skey    = cookie.value

                if cookie.name == 'ptcz':
                    self.ptcz    = cookie.value

            if self.ptwebqq:
                return False
            else:
                return True

    def check_verify_code(self, uin=None, appid=None):
        login_sig= self.check_login_sig()

        print u'1.开始检查是否需要输入验证码'
        """
        算出用户名加密后的字符串
        """
        if uin==None:
            uin=self.uin

        #GET https://ssl.ptlogin2.qq.com/check?uin=2476202050&appid=1003903&js_ver=10079&js_type=0&login_sig=5Vyb8yT91BH5ZVR3AXrb7Cx-v2PuQ3LhXwCM-3MquWEdgXt005k3SjaGaf4jy1TF&u1=http%3A%2F%2Fweb2.qq.com%2Floginproxy.html&r=0.31033543101511896 HTTP/1.1

        verifyURL = 'https://ssl.ptlogin2.qq.com/check?uin=%(uin)s&appid=%(appid)s&js_ver=10079&js_type=0&login_sig=%(login_sig)s&u1=http%%3A%%2F%%2Fweb2.qq.com%%2Floginproxy.html&r=%(randstamp)s' % {'uin':uin, 'appid':WEBQQ_APPID, 'randstamp':random.random(), 'login_sig':login_sig}
        print 'GET', verifyURL
        headers={}
        headers['Connection'] = 'keep-alive'
        """
        获取初次加密所需要的一个关键参数值
        """
        '''
        cookies_attrs=[]
        _keys=[]
        needed_cookie_names=['uikey','pgv_pvid','pgv_info','chkuin']
        for index,cookie in enumerate(self.cookiejar):
            _keys.append(cookie.name)
            if cookie.domain.endswith('.qq.com') or cookie.domain.endswith('.ptlogin2.qq.com'):
                #if cookie.name in needed_cookie_names:
                if ((cookie.value is not None) and
                    self.cookiejar.non_word_re.search(cookie.value)):
                    value = self.cookiejar.quote_re.sub(r"\\\1", cookie.value)
                else:
                    value = cookie.value

                if cookie.value is None:
                    cookies_attrs.append(cookie.name)
                else:
                    cookies_attrs.append("%s=%s" % (cookie.name, value))

        print cookies_attrs
        if not 'chkuin' in _keys:
            cookies_attrs.append("%s=%s" % ('chkuin', self.uin))

        cookies='; '.join(cookies_attrs)
        print cookies
        response = self.get(verifyURL, headers = headers, cookies=cookies)
        '''
        import cookielib
        version = 0
        name='chkuin'
        value=self.uin
        port = None
        port_specified=None
        domain, domain_specified, domain_initial_dot='ptlogin2.qq.com', None, None
        path, path_specified = '/',None
        secure = None
        expires = None
        discard = None
        comment = None
        comment_url = None
        rest = {}
        c = cookielib.Cookie(version,
                      name, value,
                      port, port_specified,
                      domain, domain_specified, domain_initial_dot,
                      path, path_specified,
                      secure,
                      expires,
                      discard,
                      comment,
                      comment_url,
                      rest)
        self.cookiejar.set_cookie(c)
        response = self.get(verifyURL, headers = headers)
        print response

        """
        对response的文本进行提取，第一步拆分成["ptui_checkVC('0'", "'!YQL'", " '\\x00\\x00\\x00\\x00\\x95\\x22\\xea\\x8a');"]
        """
        # ptui_checkVC('0','!T23','\x00\x00\x00\x00\x01\xe4\xfa\x78');
        # ptui_checkVC('2','','\x00\x00\x00\x00\x00\x00\x27\x10');

        content=response
        content = content.split(',')
        """
        提取用于生成加密后的密码的验证字符串1——!YQL 长度一般为4, 如果大于4, 说明需要验证码
        """
        verify_code1 = content[1][1:-1]

        """
        提取用于生成加密后的密码的验证字符串2——\x00\x00\x00\x00\x95\x22\xea\x8a
        是我们QQ号码的16进制形式， QQ号为：1213200914（我的qq），
        我们把\x00\x00\x00\x00\x48\x4f\xfa\x12中的\\x去掉之后就剩下484ffa12,
        我们用计算器转换一下这个数为10进制，便是1213200914
        """
        verify_code2 = content[2].split("'")[1]
        print 'verify_code1',verify_code1
        print 'verify_code2',verify_code2

        """
        判断是否出现图片验证码，这里为了图方便判断验证码1是否是4位，不是则为出现图片验证码。其实更好的方法是判断ptui_checkVC('0'"，如果是0，则是文字验证，如果是1则为图片验证
        """
        if len(verify_code1) > 4:
            # 获取验证码图片 http://captcha.qq.com/getimage?aid=1003903&&uin=qq号码&vc_type=verify_code2
            # 这里不处理验证码的问题
            print 'Your QQ need capcha to login.'
            with open('./verify.png','wb') as ff:
                verify_image_url = 'https://ssl.captcha.qq.com/getimage?aid=1003903&&uin=%(uin)s&cap_cd=%(verify_code1)s' % {'uin':self.uin,'verify_code1':verify_code1}
                ff.write(self.get(verify_image_url))

            import os
            os.system('verify.png')

            verify_code1 = raw_input('Please input verify code:')
            verify_code1 = verify_code1.strip()
        else:
            print '不需要输入验证码, 可以进行下一步登录QQ应用平台了.'

        print 'verify_code1',verify_code1
        print 'verify_code2',verify_code2
        self.verify_code1, self.verify_code2 = (verify_code1, verify_code2)
        return (verify_code1, verify_code2)

    def login(self, username=None, password=None):
        if username and password:
            self.uin      = username
            self.username = username
            self.password = password

            if not self.need_login_ptlogin2():
                print u'无需登录ptlogin2, 直接使用现有session数据登录qqapi接口'
                if not self.need_login_web2(): # 不需要登录 qqapi了, 这表示登录成功, 以后可以发消息 获取用户信息等操作了
                    print '操作qqapi的重要参数已经获取, 不需要重新登录qqapi接口'
                    return True
                else: #webqqcom 登录之后的检查参数
                    print u'操作qqapi的重要参数还未获取, 需要继续登录qqapi接口'
                    print u'登录qqapi接口...'
                    if self.login_web2():
                        print u'成功登陆qqapi接口!'
                        return True
                    else:
                        print '本地session可能过期, 将尝试从webqqcom开始登录...'
                        result = False
                        if not self.need_verify_image():
                            if self.login_webqqcom():
                                result = self.login_qqapi()
                        return result
            else:#不需要登录 webqqcom, 直接去登录 qqapi 接口
                print u'需要登录QQ应用平台'
                #GET http://ptlogin4.web2.qq.com/check_sig?pttype=1&uin=2476202050&service=login&nodirect=0&ptsig=wX3EueUa9qphimqdbBI4IIMNx7Onbm8rNKwrKLU48hM_&s_url=http%3A%2F%2Fweb2.qq.com%2Floginproxy.html%3Flogin2qq%3D0%26webqq_type%3D10&f_url=&ptlang=2052&ptredirect=100&aid=1003903&daid=164&j_later=0&low_login_hour=0&regmaster=0&pt_login_type=1&pt_aid=0&pt_aaid=0&pt_light=0
                verify_code1, verify_code2 = self.check_verify_code()
                if not self.login_ptlogin2(username=username, password=password, verify_code1=verify_code1, verify_code2=verify_code2):
                    print u'登录QQ应用平台失败'
                    #raise WebQQException(u'登录QQ应用平台失败')
                    self.runflag = False
                    return False

                print u'登录QQ应用平台成功, 开始登录WebQQ聊天接口...'
                if not self.login_web2():
                    print u'登录WebQQ聊天接口失败'
                    #raise WebQQException(u'登录WebQQ聊天接口失败')
                    self.runflag = False
                    return False

                self.runflag = True
                return True
        self.set_runflag(True)
        return True

    def logout(self):
        pass

    def heartbeat(self):
        print 'Bom..bong!'

    def poll(self):
        return 'poll'

    def handle(self, data):
        print data

    def get_handlers(self):
        return [self.handle]

    def set_runflag(self, value):
        self.runflag = value

    def run_forever(self):
        while self.runflag:
            self.heartbeat()
            data = self.poll()
            for handler in self.get_handlers():
                handler(data)
                self.handle_count = self.handle_count +1

            if self.handle_count < 100:
                self.set_runflag(True)
            else:
                self.set_runflag(False)
        self.logout()
        print 'Exiting...'
