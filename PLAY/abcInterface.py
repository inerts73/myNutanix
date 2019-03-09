import abc
#import http_post #This generate pic file.

class Bird(object):
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def fly(self):
        pass

class Raven(Bird):
    pass

if __name__ == '__main__':
    print 'AAA'


