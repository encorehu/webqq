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
