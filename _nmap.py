import json

import nmap3
import nmap3.exceptions

isHostUp = False

'''
80,102,443,502,530,593,789,1089-1091,1911,1962,2222,2404,4000,4840,4843,4911,9600,19999,20000,20547,34962-34964,34980,44818,46823,46824,55000-55003
'''

def scan(target_ip, arguman='-sV'):  # parametresiz
    scann = nmap3.Nmap()
    # results=scann.scan_top_ports("192.168.88.129")

    results = scann.nmap_version_detection(target_ip, arguman)
    # dosyaYazdir(results, "TumCikti")
    ### dict parse kısmı ###
    return result_parse(results, target_ip)


def result_parse(result, target_ip):
    # print("*" * 23)
    # print(result)
    # print(target_ip)
    global isHostUp
    servis_dict = {}  # dictionary
    dosyaYazdir(result, 'nmapCikti.txt')

    portlar = result[target_ip]['ports']

    print("{:>1} {:>7} {:>10} {:>10}".format("PORT", "STATE", "SERVICE", "VERSION"))
    print("{:>1} {:>7} {:>10} {:>10}".format((4 * "-"), (+ 6 * "-"), (8 * "-"), (8 * "-")))

    # HER PORTUN VERSİYON BİLGİSİ OLMADIĞI İÇİN HATA ALIYORUM. BUNU ENGELLEMEK İÇİN TRY EXCEPT VAR
    for i in range(0, len(portlar)):
        if 'version' in portlar[i]['service']:
            print(f"{portlar[i]['portid']:<8}"
                  f"{portlar[i]['state']:<8}"
                  f"{portlar[i]['service']['name']:<15}"
                  f"{portlar[i]['service']['product']} {portlar[i]['service']['version']:<5}")
            # servis_dict[portlar[i]['service']['name']] = portlar[i]['service']['version']  # versiyon sürümleri belli olan servisler taranabilsin diye
            servis_dict[portlar[i]['service']['name']] = portlar[i]['service']['version']
            continue
        print(f"{portlar[i]['portid']:<8}"
              f"{portlar[i]['state']:<8}"
              f"{portlar[i]['service']['name']:<15}"
              f"{'???':<5}")

    return servis_dict
