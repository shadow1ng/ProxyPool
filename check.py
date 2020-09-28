from termcolor import cprint
import requests
import threading
requests.packages.urllib3.disable_warnings()
# 模板
class Detect(threading.Thread):
    name = '检测代理存活性'

    def __init__(self, check_queue, vul_list):
        threading.Thread.__init__(self)
        self.check_queue = check_queue      # 存活web的队列
        self.vul_list = vul_list                    # 存储漏洞的名字和url
        self.headers =  {'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.125 Safari/537.36','Connection':'close'}

    def run(self):
        while not self.check_queue.empty():
            target = self.check_queue.get()
            self.run_detect(target)

    # 调用各种漏洞检测方法
    def run_detect(self, pool):
        # 漏洞1
        self.check(pool)

    def check(self, pool):
        checkurl = "http://httpbin.org/ip"
        checkurl1 = "http://www.baidu.com"
        checkurl = "http://myip.ipip.net/"
        proxies = {'http': "socks5://"+pool,'https': "socks5://"+pool}
        # proxies = {'http': pool,'https': pool}
        headers = {
                    'Connection': 'close',
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.110 Safari/537.36',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Encoding': 'gzip, deflate, sdch, br',
                    'Accept-Language': 'zh-CN,zh;q=0.8',
                }
        try:
            # req = requests.get(checkurl,headers=headers,proxies=proxies,timeout=3,verify=False)
            req1 = requests.get(checkurl1,headers=headers,proxies=proxies,timeout=3,verify=False)
            # print(req.text)
            # if req.status_code == 200 and req1.status_code == 200:
            if req1.status_code == 200:
                print(pool)
                self.vul_list.append(pool)
        except Exception as e:
            print(e)
            pass

        if 1:
            try:
                # req = requests.get(checkurl,headers=headers,proxies=proxies,timeout=3,verify=False)
                req1 = requests.get(checkurl,headers=headers,proxies=proxies,timeout=3,verify=False)
                # print(req.text)
                # if req.status_code == 200 and req1.status_code == 200:
                if req1.status_code == 200:
                    print(pool)
                    # print(req1.text)
                    self.vul_list.append(pool)
            except Exception as e:
                # print(e)
                pass
    
def quchong(vul_list):
    vul_list=list(set(vul_list))
    print(vul_list)
    print("代理存活数量: ",len(vul_list))
    flive = open("alive.txt","w")
    for one in vul_list:
        flive.write(one+"\n")
    flive.close()

def get_pool(check_queue,check_file):
    fhttp = open(check_file,"r")
    HttpPool=set()
    for one in fhttp:
        HttpPool.add(one.strip())
    HttpPool = list(HttpPool)
    fhttp.close()

    quc = open(check_file,"w")
    for one in HttpPool:
        quc.write(one+"\n")
        check_queue.put(one)
    quc.close()

if __name__ == '__main__':
    from queue import Queue

    vul_list = []
    check_queue = Queue() 
    check_file = "socks.txt"
    get_pool(check_queue,check_file)
    threads = []
    thread_num = 100  # 漏洞检测的线程数目

    for num in range(1, thread_num + 1):
        t = Detect(check_queue, vul_list)  
        threads.append(t)
        t.start()
    for t in threads:
        t.join()
    quchong(vul_list)
    
