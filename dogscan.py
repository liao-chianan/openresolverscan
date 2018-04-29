from netaddr import *
from threading import Thread
from dns import resolver
import socket
import time

#定義掃描IP來源檔案，逐行讀取，每一行格式為 XX學校,192.168.x.x/24
iplist = 'iplist2.txt'

#掃描TCP 53 port，若有開放則進行dns lookup測試google.com
def openresolver_test(school_name, test_ip, report_file, ns_num):
#          print(test_ip,end='')
          socket.setdefaulttimeout(0.1)
          sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
          result = sock.connect_ex((str(test_ip), 53))       
          num_add = 0 
          if result == 0 :
               num_add = num_add +1
               res = resolver.Resolver()
               res.nameservers = [str(test_ip)]
               try:
                   answers = res.query('google.com', 'A')[0]
                   scan_ip_report = str(school_name + '的DNS Server:' + str(test_ip) + '-[Accept Query google.com:' + str(answers) +  ']--對外開放遞迴查詢!!\n')
                   print(scan_ip_report)
                   fp = open(report_file, "a")
                   fp.write(scan_ip_report)
                   fp.close()                   
               except:
                   scan_ip_report = str(school_name + '的DNS Server:' + str(test_ip) + '-[Refused Query google.com]--未開放\n')
                   print(scan_ip_report)
                   fp = open(report_file, "a")
                   fp.write(scan_ip_report)
                   fp.close()
          sock.close()

          return num_add
#掃描UDP 53 port，若有開放則進行dns lookup測試google.com
def openresolver_udp_test(school_name, test_ip, report_file):
#         print(test_ip,end='')
          socket.setdefaulttimeout(0.1)
          udpsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
          udpresult = udpsock.connect_ex((str(test_ip), 53))                
          if udpresult == 0 :               
               res = resolver.Resolver()
               res.nameservers = [str(test_ip)]
               try:
                   answers = res.query('google.com', 'A')[0]
                   scan_ip_report = str(school_name + '的UDP DNS Server:' + str(test_ip) + '-[Accept Query google.com:' + str(answers) +  ']--對外開放遞迴查詢!!\n')
                   print(scan_ip_report)
                   fp = open(report_file, "a")
                   fp.write(scan_ip_report)
                   fp.close()                   
               except:
                   scan_ip_report = str(school_name + '的UDP DNS Server:' + str(test_ip) + '-[Refused Query google.com]--未開放\n')
                   print(scan_ip_report)
                   fp = open(report_file, "a")
                   fp.write(scan_ip_report)
                   fp.close()
          udpsock.close()             

#建立掃描紀錄檔案
scan_time = str(time.strftime("%Y%m%d-%H%M%S", time.localtime()))
report_file = str('Report-' + scan_time + '.txt')
fp = open(report_file, "a")
fp.write("\n\nOpen Resolver 掃描起始時間" + scan_time + "\n\n")
fp.close()

#讀取iplist開始掃描
for line in open(iplist):
     school_name = str(line.split(',')[0])
     school_time = str(time.strftime("%Y%m%d-%H%M%S", time.localtime()))
     scan_school = str('--掃描時間:' + school_time + '--' + line.split(',')[0] + '：' + line.split(',')[1])
     print(scan_school);
     fp = open(report_file, "a")
     fp.write(scan_school)
     fp.close()
     schoolcidr = str(line.split(',')[1])
     ns_num = 0
     #進行tcp port 53掃描，socket開啟則進行lookup google.com測試
     for ip in IPSet([schoolcidr]):
        ns_num_add = openresolver_test(school_name,ip,report_file,ns_num)
        ns_num = ns_num + ns_num_add

     print("檢測到",str(ns_num),"台TCP DNS Server")

     #如果網段中檢測不到tcp port 53開放，改成測UDP 53 port，因udp 53 hijacking導致測試時間過長暫不使用
     #if ns_num == 0 :
     #         print("網段中檢測不到Tcp 53 port 開放，案情並不單純，改成檢測UDP 53 port")
     #         for ip in IPSet([schoolcidr]):
     #             openresolver_udp_test(school_name,ip,report_file)
                  
        
#寫入結束時間
end_time = str(time.strftime("%Y%m%d-%H%M%S", time.localtime()))
fp = open(report_file, "a")
fp.write("Open Resolver 掃描結束時間" + end_time)
fp.close()