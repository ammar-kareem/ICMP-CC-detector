"""
                Covert Communications CSEC 750
            ICMP FUZZY LOGIC COVERT CHANNEL DETECTION

Description: Detection code of covert channels in ICMP medium through deep state packet inspection and fuzzy logic control system
Language: Python3
Authors: Ammar, Rashed, Qusai
                        
"""
import time
import threading
import numpy as np
import skfuzzy as fuzz
from scapy.all import *
from skfuzzy import control as ctrl



"""
1 - time stamp each packet
2 - when rate spikes, put a timestamp frame
3 - all packets within that rate can be considered for inspection
"""

def handle_icmp(packets):
    """
    Performs deep packet inspection of a given array of packets and returns binary score of either 1 or 0 for
    four factors: payload size, payload pattern, corresponding reply and ICMP rate spike.

    patameters:
    -----------

    packets: list of Scapy Packet objects

    returns:
    --------

    results: list of integers (1 or 0) representing classification score of factors
    """

    #try:
        
    if len(packets) == 0:
        return 1

    print("PACKET COUNT: ",len(packets))

    #start_time = time.time()

    packets.sort(key=lambda pkt: pkt.time)
        
    interval = (packets[0].time, packets[-1].time) # time interval of packets


    # payload patterns 
    WINDOWS_PATTERN = '6162636465666768696a6b6c6d6e6f7071727374757677616263646566676869'
    LINUX_PATTERN = '6b000d0000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637'

    # our assumed "normal" ICMP traffic rate
    time_interval = 3
    icmp_threshold = 10

    # binary scores
    size_check    = 0
    pattern_check = 0
    rate_check    = 0
    reply_check   = 0
        
    requests_id = set()
    replies_id = set()

    # calculate the ICMP rate of captured packets
    icmp_count = len(packets)
    icmp_rate = icmp_count / time_interval
    threshold_rate = 9/3

    for packet in packets:
        
        # we check if its type 8 which is request
        if packet[ICMP].type == 8: # if it is a echo request
            requests_id.add(packet[ICMP].id) # add ID it to requesters set

        elif packet[ICMP].type == 0: # if it is a echo reply
            replies_id.add(packet[ICMP].id) # add ID it to repliers set
            
            
        size = len(packet['ICMP'].payload)  # size of the ICMP
            
        
        if size != 32 or size != 64: # if it is not 32 or 64 bytes then its modified
            size_check = 1

        if packet[ICMP].haslayer(Raw): # some modified packets have no payload
            
            payload = packet[ICMP].load
            payload_pattern = payload[:].hex() # payload pattern of ICMP
            print("\nICMP payload pattern:", payload_pattern)

            # if it has a payload, check the payload pattern
            if payload_pattern != WINDOWS_PATTERN or payload_pattern != LINUX_PATTERN:
                pattern_check = 1

        else:
            pattern_check = 1


    for ID in requests_id:  # check if each echo request has a corresponding response
            if ID not in replies_id:
                reply_check = 1        

    print("\nICMP RATE: ", icmp_rate)
    print("\nTHRESHOLD: ", threshold_rate)
    if icmp_rate > threshold_rate: # check if the ICMP rate is an anomaly
        print("SPIKE DETECTED")
        rate_check = 1
            
    print("\nRATE VALUE: ", rate_check)
    print([size_check, pattern_check, rate_check, reply_check])

    results = [size_check, pattern_check, rate_check, reply_check]
    end_time = time.time()

    print("EXECUTION TIME: ", end_time - start_time)
    return results
    
    #except Exception as e:
        #print(e)

#################################################################################

# Define antecedents and consequent
size = ctrl.Antecedent(np.arange(0, 2, 1), 'size')
pattern = ctrl.Antecedent(np.arange(0, 2, 1), 'pattern')
rate = ctrl.Antecedent(np.arange(0, 2, 1), 'rate')
reply = ctrl.Antecedent(np.arange(0, 2, 1), 'reply')
classification = ctrl.Consequent(np.arange(0, 2, 1), 'classification')

# Define membership functions
size['low'] = fuzz.trimf(size.universe, [0, 0, 1])
size['high'] = fuzz.trimf(size.universe, [0, 1, 1])

pattern['low'] = fuzz.trimf(pattern.universe, [0, 0, 1])
pattern['high'] = fuzz.trimf(pattern.universe, [0, 1, 1])

rate['low'] = fuzz.trimf(rate.universe, [0, 0, 1])
rate['high'] = fuzz.trimf(rate.universe, [0, 1, 1])

reply['low'] = fuzz.trimf(reply.universe, [0, 0, 1])
reply['high'] = fuzz.trimf(reply.universe, [0, 1, 1])

classification['false'] = fuzz.trimf(classification.universe, [0, 0, 1])
classification['true'] = fuzz.trimf(classification.universe, [0, 1, 1])

# Rules

# true conditions
rule1 = ctrl.Rule(size['high'] & pattern['high'] & rate['high'] & reply['high'], classification['true'])
rule2 = ctrl.Rule(size['high'] & pattern['high'] & rate['high'] & reply['low'], classification['true'])
rule3 = ctrl.Rule(size['high'] & pattern['high'] & rate['low'] & reply['high'], classification['true'])
rule4 = ctrl.Rule(size['high'] & pattern['high'] & rate['low'] & reply['low'], classification['true'])
rule5 = ctrl.Rule(size['high'] & pattern['low'] & rate['low'] & reply['low'], classification['true'])
rule6 = ctrl.Rule(size['low'] & pattern['high'] & rate['low'] & reply['low'], classification['true'])
rule7 = ctrl.Rule(size['low'] & pattern['low'] & rate['high'] & reply['high'], classification['true'])
rule8 = ctrl.Rule(size['low'] & pattern['low'] & rate['low'] & reply['low'], classification['false'])
rule9 = ctrl.Rule(size['low'] & pattern['low'] & rate['high'] & reply['low'], classification['false'])
rule10 = ctrl.Rule(size['low'] & pattern['low'] & rate['low'] & reply['high'], classification['false'])


covert_ctrl = ctrl.ControlSystem([rule1, rule2, rule3, rule4, rule5, rule6, rule7, rule8, rule9, rule10])

while True:
    packets = sniff(filter="icmp", timeout=3)
    results = handle_icmp(packets)
    
    if results == 1:
        continue


    covert_sim = ctrl.ControlSystemSimulation(covert_ctrl)

    covert_sim.input['size'] = results[0]
    covert_sim.input['pattern'] = results[1]
    covert_sim.input['rate'] = results[2]
    covert_sim.input['reply'] = results[3]
    covert_sim.compute()

    classification = round((covert_sim.output["classification"] *10)/10)

    print("FINAL SCORE: ", classification)



