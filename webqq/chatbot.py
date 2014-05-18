class BaseChatBot(object):
    def respond(self, utext):
        return 'Say Something'

class EchoBot(BaseChatBot):
    def respond(self, utext):
        print utext
        return None

class RandomBot(BaseChatBot):
    choices = ['HeHe','let me think','Er...','Yes, you are right']

    def __init__(self, *args, **kwargs):
        default=self.choices
        self.choices=kwargs.pop('choices',default)
        super(RandomBot, self).__init__(*args, **kwargs)
        
    def respond(self, utext):
        import random
        return random.choice(self.choices)

