
import json
import re
import os

class Check_url:

    def __init__(self):
        self._cached_stamp = 0
        self.filename = 'access.log'
        self.confile = 'config.json'
        self.gtime = ''

    def validate_record (self, req_url):
        file = open(self.confile)
        data = json.load(file)
        print(req_url)

        for i in data['sqli']:
            if re.search(i, req_url):
                return True
                break

    def eval_line (self, last_line):
        # 192.168.67.128 - - [20/Jan/2021:22:14:12 +0530] "-" 408 0 "-" "-"
        tmp = last_line.split(' ')
        ip = tmp[0]
        url = tmp[6]
        tim = tmp[3].split(':', 1)[1]

        if self.gtime != tim:
            # this is a new record
            self.gtime = tim

            if self.validate_record(url):
                print("[!] Detected a malicious payload ({}), blocked the IP : {}".format(url, ip))

    def find_last (self, fname, N):

        bufsize = 8192  
        fsize = os.stat(fname).st_size
        iter = 0

        with open(fname) as f: 
            if bufsize > fsize:        
                bufsize = fsize-1
                fetched_lines = [] 

                while True: 
                    iter += 1
                    f.seek(fsize-bufsize * iter) 
                    fetched_lines.extend(f.readlines()) 
    
                    if len(fetched_lines) >= N or f.tell() == 0: 
                            line = ''.join(fetched_lines[-N:])
                            self.eval_line(line)
                            break

    def f_monitor(self):
        stamp = os.stat(self.filename).st_mtime
        if stamp != self._cached_stamp:
            self._cached_stamp = stamp
            self.find_last(self.filename, 1)

if __name__ == '__main__': 
    cu = Check_url()
      
    while True:
        try:
            cu.f_monitor()
        except Exception as e : 
            print(e)
            break