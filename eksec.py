from __future__ import print_function, unicode_literals

import socket
import _vulnersDB
import pyfiglet
from PyInquirer import prompt, Separator
from examples import custom_style_2, custom_style_1
from rich.console import Console
from venv.zaafiyet_Tarayici import _nmap, _shodann

target_ip = ""

arguman = ""


def active():
    host_solve()
    # region aktif_secim
    aktif_tarama = {
        'type': 'list',
        'qmark': '<x>',
        'name': 'aktif',
        'message': '-- Kullanılacak Tool --',
        'choices': ['nmap']
    }
    prompt(aktif_tarama, style=custom_style_2)
    # endregion #nm
    # region tanımlar
    global arguman
    script_dict = {'Siemens SIMATIC S7 PLCs': '--script s7-info',
                   'Sielco Sistemi Winlog': '',
                   'Modbus cihazları': '--script modbus-discover'}
    ics_portlar = ' -p 80,102,443,502,530,593,789,1089-1091,1911,1962,2222,2404,4000,4840,4843,4911,9600,19999,20000,20547,34962-34964,34980,44818,46823,46824,55000-55003'
    # endregion

    '''
        scriptler
        -------------------------
        Sielco Sistemi Winlog       -sT -p46824
        Siemens SIMATIC S7 PLCs     -sT -p102 --script s7-info
        Modbus Devices              -sT --script modbus-discover
        enumurate slave ID          -sT -p502 --script modbus-discover --script-args modbus-discover.aggressive=true
        BACnet Devices              -sU -p47808 --script bacnet-info            bkz. BACnet-discover-enumerate.nse
        Ethernet/IP SCADA Devices   -sU -p44818 --script enip-info
        Niagara Fox Devices         -sT -p1911,4911 --script fox-info
        ProConOS Devices            -sT -p20547 --script proconos-info
        Omrom PLC Devices           -sU/-sT -p9600 --script omrom-info
        PCWorx Devices              -sT -p1962 --script pcworx-info

    '''

    # region ics_port_onay
    ics_port_Onay = {  # zafiyetleri görüntülemek için onay
        'type': 'confirm',
        'message': 'Bilinen EKS Portları Taransın mı?',
        'name': 'isICSPort',
        'default': False,
    }
    icsport_answer = prompt(ics_port_Onay, style=custom_style_1)
    # endregion
    # region cihaz_secim
    '''scriptler, portlar, sade
        scriptleri,portlar
        portlar
        scriptler
        sade
        
        if portlar
        else if script
        else if script portlar
        
        sade
    '''

    cihaz_secim = [
        {
            'type': 'checkbox',
            'qmark': '<x>',
            'message': 'Script Seçin(Opsiyonel)',
            'name': 'cihazlar',
            'choices': [
                Separator('= Seçenekler ='),
                {
                    'name': 'Sielco Sistemi Winlog'
                },
                {
                    'name': 'Siemens SIMATIC S7 PLCs'
                },
                {
                    'name': 'Modbus cihazları'
                }
            ]
        }
    ]
    servis_dict = {}
    scriptler = prompt(cihaz_secim, style=custom_style_2)

    # endregion
    arguman = arguman + ' -sV  '
    if scriptler.get('cihazlar') == [] and icsport_answer['isICSPort'] == True:
        arguman = arguman + " " + ics_portlar
        servis_dict = _nmap.scan(target_ip, ics_portlar)

    elif scriptler.get('cihazlar') != [] and icsport_answer['isICSPort'] == False:
        for item in scriptler.get('cihazlar'):
            arguman = arguman + " " + script_dict.get(item)
        arguman = arguman + ' -sT'

        servis_dict = _nmap.scan(target_ip, arguman)

    elif scriptler.get('cihazlar') != [] and icsport_answer['isICSPort'] == True:
        for item in scriptler.get('cihazlar'):
            arguman = arguman + " " + script_dict.get(item)
        arguman = arguman + " " + ics_portlar
        arguman += ' -sT'  # script taramalarında gerekiyor.
        servis_dict = _nmap.scan(target_ip, arguman)

    elif scriptler.get('cihazlar') == [] and icsport_answer['isICSPort'] == False:
        servis_dict = _nmap.scan(target_ip)

    '''
        vuln_view = {  # zafiyetleri görüntülemek için onay
        'type': 'confirm',
        'message': 'Bulunan zafiyetler görüntülensin mi?',
        'name': 'devamMi',
        'default': True,
    }
    view_answer = prompt(vuln_view, style=custom_style_1)

    '''

    for key, value in servis_dict.items():  # servisler vulnersDBye gidiyor
        if value is None:
            print("KEY" + key)
            _vulnersDB.search(key)
        _vulnersDB.search(key, value)


def IsShodan(answer):
    return answer['pasif'] == 'shodan'


def passive():
    pasif_tarama = [
        {
            'type': 'list',
            'qmark': '<x>',
            'name': 'pasif',
            'message': '-- Kullanılacak Tool --',
            'choices': ['shodan']
        },
        {
            'type': 'list',
            'qmark': '<x>',
            'name': 'shodan',
            'message': '-- Sorgu Türü --',
            'choices': ['host', 'query'],
            'when': IsShodan
        }
    ]

    answer = prompt(pasif_tarama, style=custom_style_2)
    # print("passive answer "+str(answer)) #answer {'pasif': 'shodan', 'shodan': 'query'}

    if answer['pasif'] == 'shodan':  # tarama shodan ise query veya host olarak taramayı kontrol ediyor
        if answer['shodan'] == 'query':
            sorgu_dict = {
                'type': 'input',
                'name': 'sorgu',
                'message': 'Shodan sorgusu (*filtre kullanılamıyor*):  ',
                # 'validate': isIPValid
            }
            sorgu = prompt(sorgu_dict, style=custom_style_2)
            _shodann.search_query(sorgu)
        elif answer['shodan'] == 'host':
            host_dict = {
                'type': 'input',
                'name': 'host',
                'message': 'Host IP:  ',
                # 'validate': isIPValid
            }
            host = prompt(host_dict, style=custom_style_2)
            _shodann.search_host(host)
    # print("shodanın içi " + answer['shodan']) # query sonucu burada
    return answer['pasif']  # shodan harici seçimler buradan dönecek


def tarama_tur():
    taramaTuru = {
        'type': 'list',
        'qmark': '<x>',
        'name': 'tarama',
        'message': '-- Tarama Türü --',
        'choices': ['Aktif', 'Pasif']
    }
    answers = prompt(taramaTuru, style=custom_style_2)
    return answers['tarama']


def isIPValid(addr):
    try:
        socket.inet_aton(addr)
        # legal
    except socket.error:
        print("yanlış ip adresi")


def host_solve():
    global target_ip
    ip = [
        {
            'type': 'input',
            'name': 'ip_addr',
            'message': 'Hedef IP ',
            # 'validate': isIPValid
        }
    ]
    ip_addr = prompt(ip, style=custom_style_2)
    target_ip = ip_addr['ip_addr']
    return ip_addr['ip_addr']


def islemBirimi():
    tarama = tarama_tur()
    if tarama == 'Aktif':
        active()
    else:
        passive()


def main():
    global target_ip
    console = Console()

    ascii_banner = pyfiglet.figlet_format("EKSec")
    console.print(ascii_banner, style="green")

    # target_ip = _fastPort.GetHost(target_ip)
    # target_ip = '127.0.0.1'

    islemBirimi()


if __name__ == "__main__":
    main()
