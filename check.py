
import requests
import argparse

requests.packages.urllib3.disable_warnings()


def usage():
    print('''
    +-----------------------------------------------------------------+
    Vulnerability name: F5 BIG-IP iControl Rest API exposed Check
    Function: single detection, batch detection                                    
    Single detection：python exp.py -u url
    Batch detection：python exp.py -f url.txt
    Check: python check.py -f url.txt
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
