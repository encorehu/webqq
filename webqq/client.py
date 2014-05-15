# -*- coding: utf-8 -*-

from webclient import WebBrowser

class WebQQClient(WebBrowser):
    def __init__(self, *args, **kwargs):
        self.handle_count = 0
        self.set_runflag(False)

    def login(self, username=None, password=None):
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
