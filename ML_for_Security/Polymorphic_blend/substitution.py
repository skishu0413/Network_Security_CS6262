#!/usr/bin/env python3

import struct
import math
import dpkt
import socket
import random
from collections import Counter
from frequency import *

def substitute(attack_payload, substitution_table):
    # Using the substitution table you generated to encrypt attack payload
    # Note that you also need to generate a xor_table which will be used to decrypt
    # the attack_payload
    # i.e. (encrypted attack payload) XOR (xor_table) = (original attack payload)
    b_attack_payload = bytearray(attack_payload, "utf8")
    result = []
    xor_table = []
    # Based on your implementattion of substitution table, please prepare result
    # and xor_table as output

    for byte in b_attack_payload:
        s = substitution_table.get(chr(byte), [])
        if not s:
            raise ValueError(f"byte not found in substitution table: {chr(byte)}")

        frequency = sum(freq for _, freq in s)
        random_value = random.uniform(0, frequency)
        probability = 0

        for choices, freq in s:
            probability += freq
            if random_value <= probability:
                result.append(choices)
                xor_table.append(chr(byte ^ ord(choices)))
                break
            
    return (xor_table, result)

def getSubstitutionTable(artificial_payload, attack_payload):
    # You will need to generate a substitution table which can be used to encrypt the attack
    # body by replacing the most frequent byte in attack body by the most frequent byte in
    # artificial profile one by one

    # Note that the frequency for each byte is provided below in dictionay format.
    # Please check frequency.py for more details
    artificial_frequency = frequency(artificial_payload)
    attack_frequency = frequency(attack_payload)

    sorted_artificial_frequency = sorting(artificial_frequency)
    sorted_attack_frequency = sorting(attack_frequency)

    # Your code here ...
    substitution_table = {}

    for attack_char, attack_freq in sorted_attack_frequency:

        substitution_table[attack_char] = []
        remaining_attack_freq = attack_freq

        for artificial_char, artificial_freq in sorted_artificial_frequency:

            if remaining_attack_freq <= 0:
                break
            
            if artificial_freq > 0:
                freq = min(artificial_freq, remaining_attack_freq)
                substitution_table[attack_char].append((artificial_char, freq))
                remaining_attack_freq -= freq

    
    # Make sure your substitution table can be used in
    # substitute(attack_payload, subsitution_table)
    print(substitution_table)
    return substitution_table


def getAttackBodyPayload(path):
    f = open(path, 'rb')
    pcap = dpkt.pcap.Reader(f)
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        if socket.inet_ntoa(ip.dst) == "192.150.11.111": 
            tcp = ip.data
            if tcp.data == "":
                continue
            return tcp.data.rstrip()

def getArtificialPayload(path):
    f = open(path, 'rb')
    pcap = dpkt.pcap.Reader(f)
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        tcp = ip.data
        if tcp.sport == 80 and len(tcp.data) > 0:
            return tcp.data
