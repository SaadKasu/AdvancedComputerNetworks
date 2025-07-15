
import struct
 
from lib.gen import GenInts, GenMultipleOfInRange
from lib.test import CreateTestData, RunIntTest
from lib.worker import *
from scapy.layers.l2 import Ether # For L2 communication
from scapy.fields import ByteField, ShortField, IntField, FieldLenField
from scapy.all import Packet, bind_layers, get_if_hwaddr
from scapy.all import get_if_list, srp1
from scapy.all import sendp
import time
 
NUM_ITER   = 2     # TODO: Make sure your program can handle larger values
CHUNK_SIZE = 8  # TODO: Define me
 
# Custom Ethertype for out protocol 
SWITCHML_ETHERTYPE = 0x88F0 
 
class SwitchML(Packet):
    name = "SwitchMLPacket"
    fields_desc = [
        ShortField("allreduce_id", 0),    # Unique ID for the all-reduce operation
        ShortField("chunk_idx", 0),       # Index of the chunk in the all-reduce operation
        ShortField("num_chunks", 0),      # Total number of chunks in the all-reduce operation
        ByteField("worker_rank", 0)       # Rank of the worker sending this packet
    ]
 
# Bind the custom SwitchML layer to Ethernet with the custom ethertype
bind_layers(Ether, SwitchML, type=SWITCHML_ETHERTYPE)
 
def AllReduce(iface, rank, data, result, epoch):
    """
    Perform in-network all-reduce over ethernet
 
    :param str  iface: the ethernet interface used for all-reduce
    :param int   rank: the worker's rank
    :param [int] data: the input vector for this worker
    :param [int]  res: the output vector
 
    This function is blocking, i.e. only returns with a result or error
    """
    Log(f"Data: {data}, result: {result}")
    Log(f"Worker {rank}: AllReduce function entered.") # NEW LOG
    Log(f"The data here is: {data}")
    Log(f"Worker {rank}: Starting AllReduce for vector of size {len(data)}, , CHUNK_SIZE={CHUNK_SIZE}")
 
    # TODO: Implement me
    final_results = []
    total_num_elements = len(data)
    num_chunks = total_num_elements // CHUNK_SIZE
    Log("Total number of elements: %d, Number of chunks: %d" % (total_num_elements, num_chunks))
 
    # Assuming allredduce_id is unique fix values for each operation
    current_allreduce_id = epoch
    for chunk_idx_val in range(num_chunks):
        Log("Processing chunk %d/%d" % (chunk_idx_val + 1, num_chunks))
 
        s = chunk_idx_val * CHUNK_SIZE
        t = s + CHUNK_SIZE
        chunk_data = data[s:t]  # Getting current chunk
        Log("chunk_data %s: " % chunk_data)
 
        # Crafting the switchML packet
        SwitchMLPacket = SwitchML(
            allreduce_id=current_allreduce_id,
            chunk_idx=chunk_idx_val,
            num_chunks=num_chunks,
            worker_rank=rank
        )
        Log("SwitchMLPacket details: %r" % SwitchMLPacket.show(dump=True))
 
        # prepend raw data of chunk as payload for packet
        raw_chunk_payload = struct.pack('!' + 'I' * CHUNK_SIZE, *chunk_data)
        Log("Raw chunk payload: %s" % raw_chunk_payload)
 
        # Select a default broadcast mac address for the switch
        dst_mac_of_switch = 'ff:ff:ff:ff:ff:ff'
        Log("Destination mac %s for interface is %s" % (dst_mac_of_switch, iface))
 
        try:
            eth_frame = Ether(dst=dst_mac_of_switch,
                              src=get_if_hwaddr(iface),  # Use the MAC address of the interface
                              type=SWITCHML_ETHERTYPE
                             ) / SwitchMLPacket / raw_chunk_payload
 
            Log("Crafted Ethernet frame: %s" % eth_frame.show(dump=True))
 
            # Only wait for response on the last chunk
            response_pkt = srp1(
                eth_frame,
                iface=iface,
                timeout=10,  # time out for debugging purposes
                verbose=0
            )
            time.sleep(0.05)  # Delay for 50ms to give the switch time to process
        except Exception as e:
            Log("Error sending packet: %s" % str(e))
            exit(1)
        
        Log("===================== Sent last Packet, awaiting response packet:")
 
        if response_pkt and response_pkt.haslayer(SwitchML):
            Log("===================== RESPONSE RECEIVED =====================")
            Log("Received response for last chunk %d/%d \n" % (chunk_idx_val + 1, num_chunks))
            Log("Response packet details: %r" % response_pkt.show(dump=True))
 
            # Convert the payload of the data into an integer and log it
            payload_bytes = bytes(response_pkt[SwitchML].payload)
            
            if len(payload_bytes) >= 4:
                payload_int = int.from_bytes(payload_bytes[:4], byteorder='big')
                Log(f"Payload as integer: {payload_int}")
 
                # Response packet which contains aggregated data
                aggregated_raw_data = bytes(payload_bytes)
 
                # Unpack the aggregated 32-bit integers data
                aggregated_ints = struct.unpack('!' + 'I' * CHUNK_SIZE, aggregated_raw_data)
 
                Log(f"unpacking aggregated data to: {aggregated_ints}")
                tem_res = []
                # Write response results to the result vector
                for i, val in enumerate(aggregated_ints):
                    tem_res.append(val)
 
                result[s:t] = tem_res
                Log(f"result === {result}")
            else:
                Log("Payload too short to convert to integer.")
 
        else:
            Log("Error: No response received for last chunk %d" % chunk_idx_val)
            # We assume reliability, so response must be received
            exit(1)
 
 
def main():
    # Automatically select the first non-loopback interface
    iface = next(i for i in get_if_list() if not i.startswith('lo'))
    rank = GetRankOrExit()
    Log("Started...", rank)
    for i in range(NUM_ITER):
        num_elem = GenMultipleOfInRange(1, 2, 8 * CHUNK_SIZE) # You may want to 'fix' num_elem for debugging
        data_out = GenInts(num_elem)
        data_in = GenInts(num_elem, 0)
        CreateTestData("eth-iter-%d" % i, rank, data_out)
        AllReduce(iface, rank, data_out, data_in, i)
        RunIntTest("eth-iter-%d" % i, rank, data_in, True)
    Log("Done")
 
if __name__ == '__main__':
    main()
