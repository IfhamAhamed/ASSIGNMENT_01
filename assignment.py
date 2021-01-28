
import json
import re
import os

def validate_record (req_url):
    file = open('config.json')
    data = json.load(f)

    for i in data['attack_check']:
        if re.search("", req_url):
            return True
            break

def eval_line (last_line):
    # 192.168.67.128 - - [20/Jan/2021:22:14:12 +0530] "-" 408 0 "-" "-"
    tmp = last_line.split(' ')
    ip = tmp[0]
    t = tmp[3]
    print(ip)
    print(time)

    


def find_last (fname, N):

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
                        eval_line(line)
                        break

if __name__ == '__main__': 
      
    fname = 'access.log'
    N = 1
      
    while True:
        try: 
            find_last(fname, 1)
            break;
        except: 
            print('File not found')