import json

import vulners
from rich import *
from rich.console import Console
from rich.table import Table

'''
    id, description,published,modified,href,type?,cvelist,cvss['score'],vhref
'''


def search(servis, versiyon=None):
    vulners_api = vulners.Vulners(api_key="VWTHWW2K06GL45L0HQPO012IEEL051F65UCXMQ59AENIN6FU5E4NC7ND3CVSY2SY")
    results = vulners_api.search(f'{servis} {versiyon} AND order:cvss.score AND cvss.score:[5 TO 10]', limit=2)  # servisler buraya verilecek
    if results == []:
        print(f'Kayıtlı "{servis}" Zafiyeti Bulunamadı!')
        return
    yazdir(results)


def yazdir(vulnerabilities_list):
    global console, tablo
    try:
        console = Console(color_system="windows")
        tablo = Table(show_header=True, header_style="Blue")
        tablo.add_column("Vuln id", style="dim", min_width=12,max_width=20)
        tablo.add_column("CVSS")
        #tablo.add_column("description", min_width=30,max_width=40, justify="full")
        tablo.add_column("cve-list")

        for i in range(len(vulnerabilities_list)):  # 2
            for k in range(len(vulnerabilities_list[i])):  # 1 ,
                tablo.add_row(
                    str(vulnerabilities_list[i][k]['id']),
                    str(vulnerabilities_list[i][k]['cvss']['score']),
                    #str(vulnerabilities_list[i][k]['description']),
                    str(vulnerabilities_list[i][k]['cvelist'])
                )
        console.print(tablo)
    except:
        for i in range(len(vulnerabilities_list)):
            tablo.add_row(
                str(vulnerabilities_list[i]['id']),
                str(vulnerabilities_list[i]['cvss']['score']),
                #str(vulnerabilities_list[i]['description']),
                str(vulnerabilities_list[i]['cvelist'])
            )
        console.print(tablo)
