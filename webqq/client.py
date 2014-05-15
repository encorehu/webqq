class WebQQClient(object):

    def login(self, username=None, password=None):
        return True

    def logout(self):
        pass

    def heartbeat(self):
        print 'Bom..bong!'

    def poll(self):
        return 'poll'

    def handle(self, data):
        print data

    def run_forever(self):
        i=0
        while True:
            i=i+1
            if i>100:
                break
            print i
