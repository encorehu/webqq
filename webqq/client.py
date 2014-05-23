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

    def need_username(self):
        return False

    def need_password(self):
        return False

    def check_verify_code(self, uin=None, appid=None):
        verify_code1 = ''
        verify_code2 = ''
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
