class WebQQClient(object):

    def login(self, username=None, password=None):
        return True

    def logout(self):
        pass

    def run_forever(self):
        i=0
        while True:
            i=i+1
            if i>100:
                break
            print i
