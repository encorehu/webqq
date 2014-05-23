# -*- coding: utf-8 -*-

import json
import random
import time

from webclient import WebBrowser

from protocol import (WEBQQ_APPID,
    get_timestamp,
    get_clientid,
    get_password,
    )

import logging
logger=logging.getLogger('webclient.webqq')

class WebQQException(Exception):
    pass

class WebQQClient(WebBrowser):
    def __init__(self, *args, **kwargs):
        super(WebQQClient, self).__init__(*args, **kwargs)
        self.handle_count = 0
        self.clientid = get_clientid()
        self.msg_id   = random.randint(19990909,99999999)
        self.psessionid = ''
        self.ptwebqq    = ''
        self.vfwebqq    = ''
        self.skey       = ''
        self.uin      = kwargs.pop('username', None)
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

    def check_login_sig(self):
        '''添加检查登录签名函数 check_login_sig, 没有这个, 登录的时候可能不能获得正确的跳转链接'''
        login_sig_url = 'https://ui.ptlogin2.qq.com/cgi-bin/login?daid=164&target=self&style=5&mibao_css=m_webqq&appid=1003903&enable_qlogin=0&no_verifyimg=1&s_url=http%3A%2F%2Fweb2.qq.com%2Floginproxy.html&f_url=loginerroralert&strong_login=0&login_state=10&t=20131202001'
        referer = 'http://web2.qq.com/webqq.html'
        print 'GET', login_sig_url
        content =self.get(login_sig_url, referer=referer)
        #var g_login_sig=encodeURIComponent("5Vyb8yT91BH5ZVR3AXrb7Cx-v2PuQ3LhXwCM-3MquWEdgXt005k3SjaGaf4jy1TF"); //安全参数
        f1='var g_login_sig=encodeURIComponent("'
        f2='");'
        pos1=content.find(f1)
        pos2=content.find(f2, pos1)
        login_sig = content[pos1+len(f1):pos2]
        print 'login_sig',login_sig
        self.login_sig = login_sig
        return login_sig

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
        loginURL  = 'https://ssl.ptlogin2.qq.com/login?'

        data ={
            'u':self.uin,
            'p':get_password(password, verify_code1, verify_code2), #对密码进行加密
            'verifycode':verify_code1,
            'webqq_type':'10',
            'remember_uin':'1',
            'login2qq':'0',# 有的人是1
            'aid':'1003903',
            'u1':'http://web2.qq.com/loginproxy.html?login2qq=0&webqq_type=10',
            'strong':'true',
            'h':'1',
            'ptredirect':'0',
            'ptlang':'2052',
            'daid':'164',
            'from_ui':'1',
            'pttype':'1',
            'dumy':'',
            'fp':'loginerroralert',
            'action':'4-19-23387',
            'mibao_css':'m_webqq',
            't':'1',
            'g':'1',
            'js_type':'0',
            'js_ver':'10079',
            'login_sig':self.login_sig,
            'pt_uistyle':'5'
        }

        import urllib
        query_string = urllib.urlencode(data)
        #print 'query_string',query_string

        loginURL=loginURL+query_string
        #loginURL='https://ssl.ptlogin2.qq.com/login?u='+self.uin+'&p='+get_password(password, verify_code1, verify_code2)+'&verifycode='+verify_code1+'&webqq_type=10&remember_uin=1&login2qq=0&aid=1003903&u1=http%3A%2F%2Fweb2.qq.com%2Floginproxy.html%3Flogin2qq%3D0%26webqq_type%3D10&h=1&ptredirect=0&ptlang=2052&daid=164&from_ui=1&pttype=1&dumy=&fp=loginerroralert&action=4-19-23387&mibao_css=m_webqq&t=1&g=1&js_type=0&js_ver=10079&login_sig='+self.login_sig+'&pt_uistyle=5'

        print 'GET', loginURL
        """
        添加http的header头，一定要添加referer,腾讯服务器会判断, 否则登录不成功
        """
        #self.headers['Referer'] = 'http://web2-b.qq.com/proxy.html'
        headers = {}
        headers['Referer'] = 'https://ui.ptlogin2.qq.com/cgi-bin/login?daid=164&target=self&style=5&mibao_css=m_webqq&appid=1003903&enable_qlogin=0&no_verifyimg=1&s_url=http%3A%2F%2Fweb2.qq.com%2Floginproxy.html&f_url=loginerroralert&strong_login=0&login_state=10&t=20131202001'
        headers['Connection'] = 'keep-alive'

        """
        获取登录令牌第一部分，如果要写的健壮一些，那么这里可以对返回数据做一个验证，
        正常登陆返回
        ptuiCB('0','0','http://t.qq.com','1','登录成功！', '娱讯传媒');
        错误的返回
        ptuiCB('7','0','','0','很遗憾，网络连接出现异常，请您稍后再试。(124780859)', '2476202050');
        ptuiCB('4','0','','0','您输入的验证码不正确，请重新输入。', '2476202050');


        可以验证第一个0，如果不是0，那么就是不正常登陆
        """

        #pgv_pvid=936990096; pgv_info=ssid=s3561591060&pgvReferrer=;
        import cookielib
        version = 0
        name='pgv_pvid'
        value='936990096'
        port = None
        port_specified=None
        domain, domain_specified, domain_initial_dot='ui.ptlogin2.qq.com', None, None
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
        c.name='pgv_info'
        c.value='ssid=s3561591060&pgvReferrer='
        self.cookiejar.set_cookie(c)

        response=self.get(loginURL, headers=headers)

        content = response
        print content,type(content)

        check_url = content.split("','")[2]
        if check_url.startswith('http'):
            self.get(check_url)
        else:
            print u'登录QQ应用平台失败了'
            return False

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
        # 看看 这个机器人还需不需要再次登录http://web2.qq.com
        # vfwebqq 的值是未注销之前的值, 如果有值, 说明cookie或者内存中有这个值, 机器人还处于未注销的状态, 就不需要再次登录网站了
        print 'vfwebqq',repr(self.vfwebqq)
        print 'psessionid',repr(self.psessionid)
        print 'Boolean', repr(self.vfwebqq and self.psessionid)
        if self.vfwebqq =='' and self.psessionid =='':
            print u'qqapi接口重要参数是空值!!!!!需要获取这些重要参数'
            return True
        else:
            print u'qqapi接口重要参数是:',self.vfwebqq, self.psessionid
            return False

    def login_web2(self):
        '''登录WEBQQ聊天接口'''
        """ webQQ登录流程
        1. 输入框中输入QQ号码之后, 点击密码框的时候, 会触发 请求验证码 事件,访问http://check.ptlogin2.qq.com/ 看看你的账号是否异常, 如果正常就不需要验证码
        2. 对输入的密码进行加密后, 提供QQ号码, 加密后的密码到'http://ptlogin2.qq.com/login?' 进行验证登录, 这个时候只是相当于登录了web.qq.com这个网站
        3. 登录qq. 根据第二步中的返回结果, 得到加密的字符串, 访问  最终登录了QQ.
        """



        """http://d.web2.qq.com/channel/login2
        访问qq真实登录地址，获取登录令牌第二部分——最后补全的cookies,如果不能获取，则代表登录出现问题

        提交数据 ＝ “r=%7B%22status%22%3A%22online%22%2C%22ptwebqq%22%3A%22” ＋ ptwebqq ＋ “%22%2C%22passwd_sig%22%3A%22%22%2C%22clientid%22%3A%22” ＋ clintid ＋ “%22%2C%22psessionid%22%3Anull%7D&clientid=” ＋ clintid ＋ “&psessionid=null”

        """
        #print self.cookie
        print u'3.登录qq聊天接口'
        #login_url2 = 'http://web2-b.qq.com/channel/login'
        #self.headers['Referer'] = 'http://web2-b.qq.com/proxy.html'

        login_url2 = 'http://d.web2.qq.com/channel/login2'
        headers={}
        headers['Referer'] = 'http://d.web2.qq.com/proxy.html?v=20110331002&callback=1&id=3'
        #print 'POST', login_url2

        #登陆成功之后, 浏览器用的地址, 实际上程序用不着
        #login_url2 = 'http://web.qq.com/loginproxy.html?login2qq=0&webqq_type=10'
        #print 'GET', login_url2
        #self.headers['Referer'] = 'http://ui.ptlogin2.qq.com/cgi-bin/login?target=self&style=5&mibao_css=m_webqq&appid=1003903&enable_qlogin=0&no_verifyimg=1&s_url=http%3A%2F%2Fweb.qq.com%2Floginproxy.html&f_url=loginerroralert&strong_login=0&login_state=10&t=20121029001'

        #post_data = 'r={"status":"","ptwebqq":"%s","passwd_sig":"","clientid":"97923442"}' % self.ptwebqq
        post_data = 'r={"status":"online","ptwebqq":"%s","passwd_sig":"","clientid":"%s","psessionid":null}&clientid=%s&psessionid=null' % (self.ptwebqq,self.clientid,self.clientid)
        #print post_data

        """ 'r={"status":"","ptwebqq":"{1}","passwd_sig":"","clientid":"{2}"}' """
        import urllib
        post_data = urllib.quote(post_data,safe='=')



        """
        获得完整的登录令牌
        """
        #post_data = urllib.urlencode(post_data)
        #response = self.opener.open(login_url2, post_data, self.timeout )
        response = self.post(login_url2, data=post_data, headers=headers)
        #print 'REALURL',
        #print response.geturl()
        #print response.info()

        content  = response
        print content

        '''# 登录qq聊天接口返回的cookie中的值, 用于后续获取用户列表和群列表, 发言等等功能'''
        #
        #print 'Cookies..........'
        #for index,cookie in enumerate(self.cookie):
        #    #print index,":",cookie
        #    print cookie.name, cookie.value

        try:
            json_data = json.loads(content,encoding='utf-8')
        except ValueError as e:
            print e
        else:
            # 获取 vfwebqq 和 psessionid
            retcode = json_data['retcode']
            if retcode == 0:
                print u'正常登录qqapi接口'
                try:
                    print u'从返回的数据中获取用于操作 qqapi 接口的必要信息'
                    self.vfwebqq    = json_data['result']['vfwebqq']
                    self.psessionid = json_data['result']['psessionid']
                    self.cookiejar.save()
                    print u'重要信息获取成功'
                    return True
                except KeyError:
                    self.vfwebqq    = ''
                    self.psessionid = ''
                    print '未能正常获取用于操作 qqapi 接口的必要信息, 登录失败.'
                    return False
            elif  retcode == 103 or retcode ==121:
                print u'连接不成功，需要重新登录'
                self.logged_in = False
                return False

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

    def logout(self):
        api_url   = 'http://d.web2.qq.com/channel/logout2?ids=&clientid=%s&psessionid=%s&t=%s' % (self.clientid, self.psessionid, get_timestamp())
        post_data = None

        headers={}
        headers['Referer'] = 'http://d.web2.qq.com/proxy.html?v=20110331002&callback=1&id=3'

        content = self.get(api_url, data=post_data, headers=headers)
        print '%s logout...' % self.uin
        print content
        self.cookiejar.save()
        self.vfwebqq    = ''
        self.psessionid = ''
        self.clientid   = 0

    def heartbeat(self):
        print 'Bom..bong!', self.handle_count

    def poll(self):
        poll_url='http://d.web2.qq.com/channel/poll2'
        headers = {'Referer': 'http://d.web2.qq.com/proxy.html?v=20110331002&callback=1&id=3'}
        r = {'clientid':self.clientid,'psessionid':self.psessionid,'key':0,'ids':[]}

        data = {
            'r':json.dumps(r, separators=(',',':')),
            'clientid':self.clientid,
            'psessionid':self.psessionid
        }

        response = self.post(poll_url, data, headers=headers)
        messages = json.loads(response)
        return messages

    def handle(self, data):
        print data

    def get_handlers(self):
        return [self.handle]

    def get_msg_id(self):
        self.msg_id +=1
        return self.msg_id

    def send_group_message(self, to_group_uin, msg):
        '''

        @to_group_uin: unicode string
        @msg: utf-8 string
        '''
        if isinstance(to_group_uin, unicode):
            to_group_uin=str(to_group_uin)

        if isinstance(to_group_uin, long):
            to_group_uin=str(to_group_uin)

        if isinstance(self.psessionid, unicode):
            self.psessionid=str(self.psessionid)

        api_url ='http://d.web2.qq.com/channel/send_qun_msg2'
        headers ={'Referer':'http://d.web2.qq.com/proxy.html?v=20110331002&callback=1&id=3'}
        t='''{"group_uin":%(group_uin)s,"content":"[\"%(message)s\",[\"font\",{\"name\":\"宋体\",\"size\":\"10\",\"style\":[0,0,0],\"color\":\"000000\"}]]","msg_id":%(msg_id)s,"clientid":"%(clientid)s","psessionid":"%(psessionid)s"}'''
        #print type(to_group_uin)
        #print type(msg)
        #print type(self.clientid)
        #print type(self.psessionid)

        msg_id=self.get_msg_id()

        t=t % {
                'group_uin':to_group_uin, # if to_group_uin is unicode, and msg is utf-8, will cause error:
                'message':msg,            # UnicodeDecodeError: 'ascii' codec can't decode byte 0xe5 in position 37: ordinal not in range(128)
                'msg_id':msg_id,
                'clientid':self.clientid,
                'psessionid':self.psessionid
        }
        data = {
            'r':t,
            'clientid':self.clientid,
            'psessionid':self.psessionid
        }
        ###print data
        import urllib

        #print urllib.urlencode(data)
        print 'send', msg.decode('utf-8')

        r={}
        r['group_uin']   = to_group_uin

        content = []
        content.append(msg)
        #content.append('')
        #content.append('')
        font = {
            'name':'宋体',
            'size':'10',
            'style':[0,0,0],
            'color':'000000'
        }

        content.append(['font', font])


        r['content']    = json.dumps(content, separators=(',',':'))
        r['msg_id']     = msg_id
        r['clientid']   = self.clientid
        r['psessionid'] = self.psessionid
        #print r
        ##print '-'*80
        ##print json.dumps(r, separators=(',',':'))
        ##print '-'*80
        ##print urllib.urlencode({'r':json.dumps(r, separators=(',',':'))})

        #print repr(json.dumps(r, separators=(',',':')))

        #data = json.dumps(r, separators=(',',':'))
        data = {
            'r':json.dumps(r, separators=(',',':')).encode('utf-8'),
            'clientid':self.clientid,
            'psessionid':self.psessionid
        }

        response = self.post(api_url, data, headers=headers)
        #print response
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
