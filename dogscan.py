from netaddr import *
from threading import Thread
from dns import resolver
import socket
import time

# 定義掃描IP來源檔案，逐行讀取，每一行格式為 XX學校,192.168.x.x/24
iplist = 'tplist.txt'
timeout = 10

# 掃描網域中的NS Server並進行測試
def scan_domain_ns_test(school_domain, reportfile):
    res = resolver.Resolver()
    res.nameservers = ['1.1.1.1']
    res.lifetime = timeout
    res.timeout = timeout
    ns_server = res.query(school_domain, 'ns')
    for i in range(len(ns_server)):
        testns = str(ns_server[i])[:-1]
        #print("測試" + testns)
        res2 = resolver.Resolver()
        res2.nameservers = [testns]
        res2.lifetime = timeout
        res2.timeout = timeout    
        try:
             answers = res2.query('google.com', tcp=True)[0]
             scan_ip_report = str(school_name + '的官方DNS Server:' + testns + '-[Accept Query google.com:' + str(answers) +  ']--對外開放遞迴查詢!!\n')
             print(scan_ip_report)
             with open(report_file, "a") as fp:
                 fp.write(scan_ip_report)
        except:
             scan_ip_report = str(school_name + '的官方DNS Server:' + testns + '-[Refused Query google.com]--未開放\n')
             print(scan_ip_report)
             with open(report_file, "a") as fp:
                 fp.write(scan_ip_report)

# 掃描TCP 53 port，若有開放則進行dns lookup測試google.com
def openresolver_test(school_name, test_ip, report_file, ns_num):
#          print(test_ip,end='')
          socket.setdefaulttimeout(0.1)
          sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
          result = sock.connect_ex((str(test_ip), 53))
          num_add = 0
          if result == 0:
               num_add += 1
               res = resolver.Resolver()
               res.nameservers = [str(test_ip)]
               res.lifetime = timeout
               res.timeout = timeout
               try:
                   answers = res.query('google.com', tcp=True)[0]
                   scan_ip_report = str(school_name + '的TCP DNS Server:' + str(test_ip) + '-[Accept Query google.com:' + str(answers) +  ']--對外開放遞迴查詢!!\n')
                   print(scan_ip_report)
                   with open(report_file, "a") as fp:
                       fp.write(scan_ip_report)
               except:
                   scan_ip_report = str(school_name + '的TCP DNS Server:' + str(test_ip) + '-[Refused Query google.com]--未開放\n')
                   print(scan_ip_report)
                   with open(report_file, "a") as fp:
                       fp.write(scan_ip_report)
          sock.close()
          return num_add

# 掃描UDP 53 port，若有開放則進行dns lookup測試google.com
def openresolver_udp_test(school_name, test_ip, report_file):
#         print(test_ip,end='')
          socket.setdefaulttimeout(0.1)
          udpsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
          udpresult = udpsock.connect_ex((str(test_ip), 53))
          if udpresult == 0:
               res = resolver.Resolver()
               res.nameservers = [str(test_ip)]
               res.lifetime = timeout
               res.timeout = timeout
               try:
                   answers = res.query('google.com', tcp=False)[0]
                   scan_ip_report = str(school_name + '的UDP DNS Server:' + str(test_ip) + '-[Accept Query google.com:' + str(answers) +  ']--對外開放遞迴查詢!!\n')
                   print(scan_ip_report)
                   with open(report_file, "a") as fp:
                       fp.write(scan_ip_report)
               except:
                   scan_ip_report = str(school_name + '的UDP DNS Server:' + str(test_ip) + '-[Refused Query google.com]--未開放\n')
                   print(scan_ip_report)
                   with open(report_file, "a") as fp:
                       fp.write(scan_ip_report)
          udpsock.close()

# 建立掃描紀錄檔案
scan_time = str(time.strftime("%Y%m%d-%H%M%S", time.localtime()))
report_file = str('Report-' + scan_time + '.txt')
with open(report_file, "a") as fp:
    fp.write("\n\nOpen Resolver 掃描起始時間" + scan_time + "\n\n")

# 讀取iplist開始掃描
with open(iplist, encoding='UTF-8') as iplist_fp:
    for line in iplist_fp:
         school_name = str(line.split(',')[0])
         school_cidr = str(line.split(',')[1])
         school_domain = str(line.split(',')[2]).rstrip()
         school_time = str(time.strftime("%Y%m%d-%H%M%S", time.localtime()))
         scan_school = str('--掃描時間:' + school_time + '--' + school_name + '：' +  school_domain +  '：'  + school_cidr)
         print(scan_school);
         with open(report_file, "a") as fp:
             fp.write(scan_school)
         schoolcidr = str(line.split(',')[1])
         ns_num = 0

         #掃描該網域內的中的NS Server並進行測試
         scan_domain_ns_test(school_domain, report_file)

         # 進行tcp port 53掃描，socket開啟則進行lookup google.com測試
         for ip in IPSet([schoolcidr]):
            ns_num_add = openresolver_test(school_name,ip,report_file,ns_num)
            ns_num = ns_num + ns_num_add

         print(school_name + "掃描53 port檢測到",str(ns_num),"台TCP DNS Server\n\n")

         #如果網段中檢測不到tcp port 53開放，改成測UDP 53 port，因udp 53 hijacking導致測試時間過長暫不使用
         #if ns_num == 0 :
         #         print("網段中檢測不到Tcp 53 port 開放，案情並不單純，改成檢測UDP 53 port")
         #         for ip in IPSet([schoolcidr]):
         #             openresolver_udp_test(school_name,ip,report_file)


#寫入結束時間
end_time = str(time.strftime("%Y%m%d-%H%M%S", time.localtime()))
with open(report_file, "a") as fp:
    fp.write("Open Resolver 掃描結束時間" + end_time)
