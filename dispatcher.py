from os import system
import argparse
import hmac
import hashlib
import json
import requests
import uuid
import random
import string
import time
from os import urandom
from string import Template
import os





def send_statham(server,json):
    SECRET_KEY = b'YOUR KEY'
    message = json
    hmac_signature = hmac.new(SECRET_KEY, str(message).encode('utf-8'), hashlib.sha256)
    hmac_hex = hmac_signature.hexdigest()
    jsondatam = {
        'message': message,
        'hmac': hmac_hex
    }

    r = requests.post("https://"+server+"/MalOne", json=jsondatam)
    
def shufb64():
        l = list("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
        random.shuffle(l)
        result = ''.join(l)
        return result.replace("/","\\\/")

def build(server,target):
    malone = str(uuid.uuid4())
    system("sed s/xXxUUIDxXx/"+malone +
           "/g recon_dist.cpp > tmpsrc/tricard."+target+".cpp")
    pat = shufb64()
    system("sed -i s/xXTricardServerXx/"+server+"/g tmpsrc/tricard."+target+".cpp")
    system("sed -i s/xXBase64CharSetXx/"+pat+"/g tmpsrc/tricard."+target+".cpp")
    system("x86_64-w64-mingw32-g++ -w -static -Os -s tmpsrc/tricard."+target +".cpp -o tmpbuild/tricard."+target+".exe -lwinhttp -liphlpapi -lz -lcrypt32 -std=c++14 -frandom-seed="+malone+" >/dev/null")
    return malone,pat.replace("\\\/","/")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Tricard is a malware sandbox fingerprinting toolset.\nhttps://github.com/therealunicornsecurity/tricard/")



    parser.add_argument('-l', nargs='+', type=str, help="Specify list of local targets, local generation only, manual dispatch", required=True)    
    parser.add_argument('-d', type=str, help="Target domain with tricard data collector", required=True)

                    
    if parser.parse_args().d:
        tricard_server = parser.parse_args().d
    if parser.parse_args().l:
        targets = parser.parse_args().l
        statham = {}
        for e in targets:
                u = build(tricard_server,e)
                statham[e+"_"+str(int(time.time()))] = list(u)
                
        send_statham(tricard_server, statham)
        print("[+] Compiled and ready, check ./tmbuild")
