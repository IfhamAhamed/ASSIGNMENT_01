import os

class Monkey(object):
    def __init__(self):
        self._cached_stamp = 0
        self.filename = 'access.log'

    def ook(self):
        stamp = os.stat(self.filename).st_mtime
        if stamp != self._cached_stamp:
            self._cached_stamp = stamp
            # File has changed, so do something...
            self.myprint()
        
    def myprint():
        print("here")


m = Monkey()

while True:
    m.ook()