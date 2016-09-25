#!/usr/bin/python3
import platform
import os
import pexpect
import signal
import sys
import threading
import time

'''
Configuration
'''
MAC = "58:70:c6:01:71:66"
gateway = "192.168.1.1"
interface = "ens33"
deadline = 999999
interval = 3

'''
Code
'''
IP = "" # IP of the destination
running = True # Is this program still alive?
changed = True # Has IP changed?
dancing = False # Is the Cell dancing？
ettercap = None # The tread of Ettercap

# All bytes forwarded last time
lastBytesOut = 0
lastBytesIn = 0

#Usual check
if platform.python_version()[0] != '3':
    print("You must trace the Cell with Python 3!")
    sys.exit(1)
if os.geteuid() != 0:
    print("You must trace the Cell as ROOT.")
    sys.exit(1)


def e(msg):
    print(time.strftime("[%Y-%m-%d %X] ", time.localtime()) + msg)


def signal_handler(signal, frame):
    global running
    e("Exiting...")
    if ettercap != None:
        end_arp()
    running = False
    sys.exit(0)


def ready():
    if IP == "":
        return False
    return True


def end_arp():
    global ettercap
    if ettercap == None:
        return
    e("Ending Ettercap...")
    ettercap.send("q")
    try:
        ettercap.expect("Unified sniffing is not running", 6)
    except:
        time.sleep(0.5)
    ettercap.close()
    ettercap = None
    e("Ettercap ended")


def new_arp():
    global changed, ettercap
    changed = False
    end_arp()
    command = "ettercap"
    args = ['-i', interface, '-T', '-o', '-M', 'arp:remote', "/" + gateway + "/", "/" + IP + "/"]
    ettercap = pexpect.spawn(command, args)
    while os.system("iptables -D FORWARD -d " + IP + " 2>/dev/null") == 0:
        pass
    while os.system("iptables -D FORWARD -s " + IP + " 2>/dev/null") == 0:
        pass
    command = "iptables -I FORWARD -d " + IP
    os.system(command)
    command = "iptables -I FORWARD -s " + IP
    os.system(command)
    getDataPackCnt()
    e("Ettercap started")


def getIP():
    global IP, changed

    e("Trying to get IP...")
    # Get ARP list
    command = "ip neigh flush dev " + interface
    os.system(command)
    command = "nmap -sP " + gateway + "/24"
    os.popen(command).read()
    command = "arp -n|grep " + MAC
    arp_raw = os.popen(command).read()

    # Try to get its IP from the list
    if len(arp_raw):
        arp = arp_raw.split()
        if (IP != arp[0]):
            IP = arp[0]
            changed = True
            e("New destination IP: " + arp[0])
    elif IP != "":
        IP = ""
        e("No destination IP found! The host may be down.")
    t = threading.Timer(300, getIP)
    t.setDaemon(True)
    t.start()


def getDataPackCnt():
    global lastBytesOut, lastBytesIn
    command = "iptables -n -v -L -t filter -x|grep FORWARD -A 99999|grep " + IP
    data = os.popen(command).read().split()
    if (len(data) != 16):
        e("Bad results from iptables!")
        return
    bakOut, bakIn = lastBytesOut, lastBytesIn
    lastBytesOut = int(data[1])
    lastBytesIn = int(data[9])
    return bakOut, bakIn


def monitor():
    global dancing
    bakOut, bakIn = getDataPackCnt()
    outSpeed, inSpeed =\
        round((lastBytesOut - bakOut) / interval / 1024, 2),\
        round((lastBytesIn - bakIn) / interval / 1024, 2)

    print("Speed of OUT: ", outSpeed, " KB/s")
    print("Speed of IN: ", inSpeed, " KB/s")

    if outSpeed > deadline or inSpeed > deadline:
        if not dancing:
            e("Warning! The Cell is dancing!")
            dancing = True
    else:
        dancing = False

def watchCat():
    while True:
        if dancing:
            alarm()
        time.sleep(1)


def alarm():
    e("Alarm")
    pass

def heartbeat():
    alarm()
    t = threading.Timer(30, heartbeat)
    t.setDaemon(True)
    t.start()


if __name__ == "__main__":
    print("[Isotope Tracing] by Moycat")
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    signal.signal(signal.SIGINT, signal_handler)
    print("Destination MAC Address: " + MAC)
    print("Deadline: " + str(deadline) + " KB/s")
    print("Gateway: " + gateway)
    print("Interface: " + interface)
    print("Interval: " + str(interval))
    e("Now pinpointing the Cell...")
    heartbeat()
    getIP()
    t = threading.Thread(target=watchCat)
    t.setDaemon(True)
    t.start()
    while True and running:
        time.sleep(interval)
        if not ready():
            continue
        if changed and ready():
            new_arp()
            continue
        monitor()