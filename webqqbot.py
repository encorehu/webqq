from webqq import WebQQClient

webqq_client = WebQQClient()
webqq_client.login(username = '12345678',
                  password = '88888888')
webqq_client.run_forever()
