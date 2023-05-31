#author yufeng.sun muyuan.yang
import sys
import random
import time
from tornado import gen
import tornado
from tornado import ioloop
from tornado import web
import tornado.httpserver
import datetime


def calc_pai(n):
    """
    :param n: 计算π的精度（位数）
    :return:
    """

    pi = 0
    for i in range(n):
        pi += 4 * (-1) ** i / (2 * i + 1)

    print("π的值为：", pi)


def dot():
    """callback for showing that IOLoop is still responsive while we wait"""
    sys.stdout.write('.')
    sys.stdout.flush()


def slow_responder(num):
    print(num)
    time.sleep(random.randint(1, 5))


# class TestHandler(web.RequestHandler):
#
#     def get(self):
#         print("get request")
#         slow_responder(5)
#         res = "get http request"
#         print(res)
#         self.write(res)
class TestHandler(web.RequestHandler):

    @gen.coroutine
    def get(self):
        start = datetime.datetime.now()
        print('get request start:', start.strftime('%Y-%m-%d %H:%M:%S.%f'))
        calc_pai(3000000)
        # slow_responder(5)
        end = datetime.datetime.now()
        print('request calc end:', end.strftime('%Y-%m-%d %H:%M:%S.%f'))
        res = str(round((end - start).total_seconds() * 1e3, 3)) + 'ms'
        print('bye--------------')
        self.write(res)


def main():
    application = web.Application([(r"/", TestHandler)])
    server = tornado.httpserver.HTTPServer(application)
    server.bind(8886)
    # specify number of subprocess
    server.start(1)
    print('service go!')
    # beat = ioloop.PeriodicCallback(dot, 100)
    # beat.start()

    try:
        ioloop.IOLoop.instance().start()
    except KeyboardInterrupt:
        print(' Interrupted')


if __name__ == "__main__":
    main()
