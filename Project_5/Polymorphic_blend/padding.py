#!/usr/bin/env python3

import struct
import math
import random
from frequency import *
from collections import Counter

def padding(artificial_payload, raw_payload):
    padding = ""
    
    # Get frequency of raw_payload and artificial profile payload
    artificial_frequency = frequency(artificial_payload)
    raw_payload_frequency = frequency(raw_payload)

    # To simplify padding, you only need to find the maximum frequency difference for each
    # byte in raw_payload and artificial_payload, and pad that byte at the end of the
    # raw_payload. 
    # Note: only consider the differences when artificial profile has higher frequency.


    # Depending upon the difference, call raw_payload.append


    # Your code here ... 
    max_freq_difference = {}
    for k in artificial_frequency:
        if artificial_frequency[k] > raw_payload_frequency.get(k, 0):
            max_freq_difference[k] = artificial_frequency[k] - raw_payload_frequency.get(k, 0)

    if max_freq_difference:
        padding = max(max_freq_difference, key=max_freq_difference.get)
        raw_payload += padding

    return raw_payload
