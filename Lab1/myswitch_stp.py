'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
from switchyard.lib.userlib import *
import time
from SpanningTreeMessage import SpanningTreeMessage

forwarding_table = dict()

def main(net):
    
    # Store all the local addresses
    my_interfaces = net.interfaces() 
    mymacs = [intf.ethaddr for intf in my_interfaces]
    valid_ports = [intf.name for intf in my_interfaces]
    all_ports = [intf.name for intf in my_interfaces]
    invalid_ports = []

    stp_enabled = True
    packet = None
    timestamp = None
    input_port = None
 
    def forward_packet(packet, ignore_port):
        for port_name in all_ports:
            if (port_name == ignore_port):
                continue
            log_debug("Forwarding packet on port {}".format(port_name))
            log_debug("Forwarding packet {}".format(packet))
            net.send_packet(port_name, packet)
        log_debug(" ")

    def construct_packet(root_id, switch_id, hops_to_root):
        # Create stp packets
        spm = SpanningTreeMessage(root_id, hops_to_root, switch_id)
        
        # Add slow header thingy
        Ethernet.add_next_header_class(EtherType.SLOW, SpanningTreeMessage)
        packet = Ethernet(src=switch_id, dst="FF:FF:FF:FF:FF:FF", ethertype=EtherType.SLOW) + spm
        return packet  


    def stp(switch_id):

        # Initially thinks the root is itself
        my_id = switch_id
        root_id = switch_id
        local_hops_to_root = 0
        root_interface = None
        last_stp_time = 0
        prev_stp_time = 0

        # Make the first packet
        packet = construct_packet(root_id, switch_id, 0)
        spm_dummy = SpanningTreeMessage(root_id, local_hops_to_root, switch_id)

        root = True # Assume that the switch is the root initially
        log_debug("Initial Packet to Send {}".format(packet))
        while (True):
            if (root):
                forward_packet(packet, None)
            # Try to recieve a packet
            try:
                # If haven't receieved a message in more than 10 secs
                if (last_stp_time > 10):
                    log_debug("Haven't received in 10 seconds, purge")
                    log_debug("Time {} - last_stp_time {}".format(time.time(), last_stp_time))
                    # Reinitialize root_id to switch's own id
                    root_id = switch_id
                    # Hop count to 0
                    local_hop_count = 0
                    # Remove all blocked interfaces
                    for port in invalid_ports:
                        invalid_ports.remove(port)
                        valid_ports.append(port)
                    # Forward packet to all interfaces
                    forward_packet(packet, None)
                else: # Usually just waiting for packet
                    timestamp,input_port,rec_packet = net.recv_packet(timeout=2)
            except NoPackets:
                # Update the last_stp_time
                # Should be 2 seconds because of timeout
                last_stp_time = last_stp_time + 2
                continue
            log_debug("")
            log_debug("Recieved Packet {}".format(rec_packet))
            log_debug("Root_id {}".format(root_id))
            log_debug("Local # hops_to_root {}".format(local_hops_to_root))
            log_debug("Valid_ports {}".format(valid_ports))
             
            if not (isinstance(rec_packet[1], type(spm_dummy))):
               return timestamp,input_port,rec_packet 
            # Update the number of hops
            rec_packet[1].hops_to_root = rec_packet[1].hops_to_root + 1

            # Recived packet from root_interface
            if (input_port == root_interface):
                # Update packet and root interface
                log_debug("Entered case 1: input_port == root_interface")
                root = False # Not root anymore
                root_interface = input_port
                prev_stp_time = last_stp_time
                last_stp_time = timestamp
                local_hops_to_root = rec_packet[1].hops_to_root
                root_id = rec_packet[1].root
                packet = construct_packet(root_id, switch_id, rec_packet[1].hops_to_root) 
                
                # "Forward Packet"
                forward_packet(packet, input_port)
            elif(rec_packet[1].root < root_id):
                log_debug("Entered case 2: rec_packet's root < root_id")
                root = False
                root_interface = input_port
                prev_stp_time = last_stp_time
                last_stp_time = timestamp
                local_hops_to_root = rec_packet[1].hops_to_root
                root_id = rec_packet[1].root
                packet = construct_packet(root_id, switch_id, rec_packet[1].hops_to_root)

                # Before forwarding, unblock all blocked ports
                for port in invalid_ports:
                    invalid_ports.remove(port)
                    valid_ports.append(port)
               
                # Forward the packet 
                forward_packet(packet, input_port)
            # If the recived packet's root is larger than assumed root
            # Remove from blocked list if present
            elif (rec_packet[1].root > root_id):
                log_debug("Entered case 3: rec_packet's root > root_id")
                for port in invalid_ports:
                    if (port == input_port):
                        invalid_ports.remove(input_port)
                        valid_ports.append(input_port)
            elif (rec_packet[1].root == root_id):
                log_debug("Entered case 4: rec_packet's root == root_id")
                if (rec_packet[1].hops_to_root + 1 < local_hops_to_root or ((rec_packet[1].hops_to_root + 1 == local_hops_to_root) and (root_id > rec_packet[1].switch_id))):
                    # Remove incoming interface from blocked interfaces (if pres)
                    log_debug("Entered if")
                    for port in invalid_ports:
                        if (port == input_port):
                            invalid_ports.remove(input_port)
                            valid_ports.append(input_port)
                    # Block original root_interface
                    for port in valid_ports:
                        if (port == root_interface):
                            valid_ports.remove(root_interface)
                            invalid_ports.append(root_interface)
                    # TODO: Update root_interface = incoming interface and other info
                    root_interface = input_port
                    last_stp_time = timestamp
                    packet = construct_packet(root_id, switch_id, rec_packet[1].hops_to_root)
                    # TODO: Forward packets taking information update into account
                    forward_packet(packet, input_port)
                else:
                    log_debug("Entered else")
                    # Block the interface
                    for port in valid_ports:
                        if (port == input_port):
                            valid_ports.remove(input_port)
                            invalid_ports.append(input_port)
            log_debug("Root_id {}".format(root_id))
    switch_id = mymacs[0]
    
    # A switch's initial root ID is it's lowest MAC address
    for val in mymacs:
        if (val < switch_id):
            switch_id = val
        log_debug("MAC {} ".format(val))

    log_debug("Switch_id {} ".format(switch_id))

    # Before sending packets and such, do stp
    #packet = stp(switch_id)
    #log_debug("Packet should be Iv4 {}".format(packet))
    def lru_update(forwarding_table_entry, packet):

        global forwarding_table

	# Find the element to remove for pop
        remove = sorted(forwarding_table.items(), key=lambda x: x[1][1])

        # Remove the first element from the sorted list
        forwarding_table.pop(remove[0][0], None)
        forwarding_table[packet[0].src] = forwarding_table_entry
        # Don't need extra sort
        #forwarding_table = sorted(forwarding_table.items(), key=lambda x: x[1][1])

    while True:
        if (stp_enabled):
            stp_enabled = False
            timestamp,input_port,packet = stp(switch_id)
        else:
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
                for port in valid_ports:
                    if port != input_port:
                        log_debug ("Flooding packet {} to {}".format(packet, port))
                        net.send_packet(port, packet)
    
    net.shutdown()
