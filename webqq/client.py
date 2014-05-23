class WebQQClient(object):
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

    def login(self, username=None, password=None):
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
