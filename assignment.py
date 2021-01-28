
import json
import re
import os

class Check_url:

    gtime = ''

    def validate_record (self, req_url):
        file = open('config.json')
        data = json.load(f)

        for i in data['attack_check']:
            if re.search("*id*", req_url):
                return True
                break

    def eval_line (self, last_line):
        # 192.168.67.128 - - [20/Jan/2021:22:14:12 +0530] "-" 408 0 "-" "-"
        tmp = last_line.split(' ')
        ip = tmp[0]
        url = tmp[6]
        tim = tmp[3].split(':', 1)[1]
        
        #print(self.gtime, tim)
        #print(tmp)
        if self.gtime != tim:
            # this is a new record
            self.gtime = tim
            print(self.validate_record(url))


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
                            # print() 
                            line = ''.join(fetched_lines[-N:])
                            self.eval_line(line)
                            break

if __name__ == '__main__': 
      
    fname = 'access.log'
    N = 1
    cu = Check_url()
      
    while True:
        try: 
            cu.find_last(fname, 1)
            # print(cu.gtime)
            break
        except Exception as e : 
            print(e)
            break