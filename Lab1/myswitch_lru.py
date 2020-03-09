'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
from switchyard.lib.userlib import *
import time

forwarding_table = dict()

def main(net):
    
    # Store all the local addresses
    my_interfaces = net.interfaces() 
    mymacs = [intf.ethaddr for intf in my_interfaces]

    def lru_update(forwarding_table_entry, packet):
        # Have to declare global because it was causing errors
        global forwarding_table

	# Find the element to remove for pop
        remove = sorted(forwarding_table.items(), key=lambda x: x[1][1])

        # Remove the first element from the sorted list
        forwarding_table.pop(remove[0][0], None)
        forwarding_table[packet[0].src] = forwarding_table_entry
        # Should be sorted

    while True:
        try: # Wait to recieve a new packet. Retruns timestamp, input port where packet recieved, and packet itself
            timestamp,input_port,packet = net.recv_packet()
        except NoPackets: # No packets recived before timeout
            continue
        except Shutdown:
            return

        log_debug ("In {} received packet {} on {}".format(net.name, packet, input_port))
        forwarding_table_entry = (input_port, timestamp)
	
        # Packet has been recieved, update LRU based on it's size
        if (packet[0].src not in forwarding_table):
            if (len(forwarding_table) >= 5):
                lru_update(forwarding_table_entry, packet)
            else:
                forwarding_table[packet[0].src] = forwarding_table_entry

        if packet[0].dst in mymacs:
            log_debug ("Packet intended for me")
        else:
            if packet[0].dst in forwarding_table:
                # Update forwarding table timestamp
                input_port_copy = forwarding_table[packet[0].dst][0]
                forwarding_table[packet[0].dst] = (input_port_copy, time.time())
                net.send_packet(forwarding_table[packet[0].dst][0], packet)
            else:
                for intf in my_interfaces:
                    if input_port != intf.name:
                        log_debug ("Flooding packet {} to {}".format(packet, intf.name))
                        net.send_packet(intf.name, packet)
    net.shutdown()

