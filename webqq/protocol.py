# -*- coding: utf-8 -*-

WEBQQ_APPID     = 1003903
WEBQQ_VERSION   = 'WebQQ3.0'


import hashlib
import time
import random


def md5hash(str):
    '''
    进行md5加密，并输出二进制值
    '''
    return hashlib.md5(str).digest()

def hex_md5hash(str):
    '''
    进行md5加密，并输出16进制值
    '''
    return hashlib.md5(str).hexdigest().upper()

def hexchar2bin(uin):
    """
    由于提取的验证码2为文本字符串，因此要把文本字符串转换成原始的字符串。
    本函数先把\x00\x00\x00\x00\x95\x22\xea\x8a切片成list如['00','00','00','00','95','22','ea','8a'],
    然后遍历这个list，对每个字符串进行转换，转换成16进制的数字，
    最后使用chr函数，把16进制的数字转换成原始字符，并合并
    """
    uin_final = ''
    uin = uin.split('\\x')
    for i in uin[1:]:
        uin_final += chr(int(i, 16))
        #print 'uin_final',uin_final
    return uin_final

def get_password(password, verifyCode1, verifyCode2):
    """
    根据明文密码计算出加密后的密码
    """
    password_1 = md5hash(password) #第一步，计算出来原始密码的MD5值，输出二进制
    password_2 = hex_md5hash(password_1 + hexchar2bin(verifyCode2)) #第二步，合并第二步产生的bin值与验证码2的bin值，并进行md5加密，输出32位的16进制
    password_final = hex_md5hash(password_2 + verifyCode1.upper()) #第三步，合并第二步产生的16进制值与验证码1，并进行md5加密，输出32位的16进制值
    return password_final

def get_username(username):
    return base64.encodestring(urllib.quote(username))[:-1]

def get_timestamp():
    return ('%0.3f' % time.time()).replace('.','')

def get_clientid():
    return ''.join(map(str, [random.randint(1,10) for x in xrange(8)]))
