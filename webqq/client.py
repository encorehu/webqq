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
        return True

    def login_ptlogin2(self, username = None, password = None, verify_code1 = None, verify_code2 = None):
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
