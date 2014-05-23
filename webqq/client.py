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
        self.clientid = get_clientid()
        self.psessionid = ''
        self.ptwebqq    = ''
        self.vfwebqq    = ''
        self.skey       = ''
        #self.uin      = uin
        #self.password = password

        self.set_runflag(False)
        print 'clientid',self.clientid

    def need_username(self):
        '''用户名是QQ登录账号(数字, 长度大于5)或者邮箱地址'''
        if self.username is None or len(self.username)<5 :
            return True
        else:
            return False

    def need_password(self):
        if self.password is None or len(self.password)<8 :
            return True
        else:
            return False

    def check_verify_code(self, uin=None, appid=None):
        print u'1.开始检查是否需要输入验证码'
        """
        算出用户名加密后的字符串
        """
        if uin==None:
            uin=self.uin
        verifyURL = 'http://check.ptlogin2.qq.com/check?uin=%s&appid=%s&r=%s' % (uin, WEBQQ_APPID, random.random())
        headers={}
        ###headers['Host'] = 'ptlogin2.qq.com'
        headers['Connection'] = 'keep-alive'
        """
        获取初次加密所需要的一个关键参数值
        """
        #print 'GET ',verifyURL
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
                verify_image_url = 'http://captcha.qq.com/getimage?aid=1003903&&uin=%(uin)s&vc_type=verify_code2' % {'uin':self.uin}
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

    def login_ptlogin2(self, username = None, password = None, verify_code1 = None, verify_code2 = None):
        '''登录QQ平台'''
        print u'2.开始登录webqq网站'
        loginURL  = 'http://ptlogin2.qq.com/login?'
        data ={
            'u':self.uin,
            'p':get_password(password, verify_code1, verify_code2), #对密码进行加密
            'verifycode':verify_code1,
            'webqq_type':'10',
            'remember_uin':1,
            'login2qq':'0',# 有的人是1
            'aid':1003903,
            'u1':'http://web.qq.com/loginproxy.html?login2qq=0&webqq_type=10',
            'strong':'true',
            'h':'1',
            'ptredirect':'0',
            'ptlang':'2052',
            'from_ui':'1',
            'pttype':'1',
            'dumy':'',
            'fp':'loginerroralert',
            't':'1',
            'g':'1',
            'action':'5-25-61202',
            'mibao_css':'m_webqq',
        }

        import urllib
        query_string = urllib.urlencode(data)
        #print 'query_string',query_string

        loginURL=loginURL+query_string
        """
        添加http的header头，一定要添加referer,腾讯服务器会判断, 否则登录不成功
        """
        #self.headers['Referer'] = 'http://web2-b.qq.com/proxy.html'
        headers = {}
        headers['Referer'] = 'http://ui.ptlogin2.qq.com/cgi-bin/login?target=self&style=5&mibao_css=m_webqq&appid=1003903&enable_qlogin=0&no_verifyimg=1&s_url=http%3A%2F%2Fweb.qq.com%2Floginproxy.html&f_url=loginerroralert&strong_login=0&login_state=10&t=20121029001'
        headers['Connection'] = 'keep-alive'

        """
        获取登录令牌第一部分，如果要写的健壮一些，那么这里可以对返回数据做一个验证，
        正常登陆返回ptuiCB('0','0','http://t.qq.com','1','登录成功！', '娱讯传媒');
        错误的返回
        ptuiCB('7','0','','0','很遗憾，网络连接出现异常，请您稍后再试。(124780859)', '2476202050');
        ptuiCB('4','0','','0','您输入的验证码不正确，请重新输入。', '2476202050');


        可以验证第一个0，如果不是0，那么就是不正常登陆
        """
        response=self.get(loginURL, headers=headers)

        content = response
        print content,type(content)

        print u'2.1 检查cookie中的数据'
        #print self.cookie.make_cookies()
        for index,cookie in enumerate(self.cookiejar):
            #print index,":",cookie
            if cookie.name == 'ptwebqq':
                self.ptwebqq = cookie.value

            if cookie.name == 'skey':
                self.skey    = cookie.value

            if cookie.name == 'ptcz':
                self.ptcz    = cookie.value
                #if index ==1:
            #    gsid = cookie.value
            print cookie.name,cookie.value #,cookie.port,cookie.path,cookie.expires

        if self.skey == '' :
            print u'虽然登录了webqqcom, 但是没有接收到下一步中必须用到的几个cookie'
            self.logged_in = False
            return False
        else:
            print u'成功登录了webqqcom, 并同时获取到了下一步中必须用到的几个cookie'
            self.logged_in = True
            return True

    def need_login_web2(self):
        return True

    def login_web2(self):
        return True

    def login(self, username=None, password=None):
        if not self.need_login_ptlogin2():
            if not self.need_login_web2():
                return True
            else:
                if self.login_web2():
                    return True
                else:
                    return False
        else:
            verify_code1, verify_code2 = self.check_verify_code()
            if not self.login_ptlogin2(username=username,password=password,verify_code1=verify_code1,verify_code2=verify_code2):
                self.set_runflag(False)
                return False

            if not self.login_web2():
                self.set_runflag(False)
                return False

        return True

    def logout(self):
        return True

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
        i=0
        while True:
            i=i+1
            if i>100:
                break
            print i
