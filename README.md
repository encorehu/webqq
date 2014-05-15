webqq
=====

python webqq, for fun.

webqq的python库已经写烂了, 似乎github上满大街都是.

然而, 总是有点不能让人满意. 不外乎:

 - 下载了, 填写了用户名密码后, 缺少各种库, 这个库又不好安装
 - 各个库平台相关性太强
 - 各种原因, 登录不了
 - 代码的口味太差
 - 库长期不更新, 跟不上webqq协议的更新和变化
 - 中文文档匮乏, 说明太简单, 简单到只有作者懂

因此, 这些种种不满意让我重新造了个轱辘.

 - 基于python2.7.x
 - 使用python标准库
 - 尽量简洁, 易懂, 好修改
 - 争取用上一种插件式的开发

废话少说, Talk is cheap, show me the code.

依赖
====

 - webclient https://github.com/encorehu/webclient 我封装的一个基于urllib2的网络通信库, 可以用来写爬虫, 反正就是好用.
 - 没了

安装
====

 - 下载 webclient 压缩包, 并解压后安装 `setup.py install`
 - 下载这个 repo的压缩包, 解压后, webqq 模块可以使用`setup.py install` 安装, 也可以修改用户名密码, 直接运行包里的**bot.py文件.


webqq调用代码
=============

    from webqq import WebQQClient
    webqq_client = WebQQClient(debug=False)
    webqq_client.login(username = '12345678',
                  password = '88888888')
    webqq_client.run_forever()

看看这个调用是不是很简单.

webqq插件自定义代码
===================

    from webqq import WebQQClient
    webqq_client = WebQQClient(debug=False)
    # 插件还没写好, 但是准备写了
    # 你可以在这里添加代码, 将会是加载自己写的插件的部分
    # 暂时接口设置为
    # webqq_client.plugins.append(yourplugin)
    # 或者
    # webqq_client.plugins = [yourplugins]
    webqq_client.login(username = '12345678',
                  password = '88888888')
    webqq_client.run_forever()
