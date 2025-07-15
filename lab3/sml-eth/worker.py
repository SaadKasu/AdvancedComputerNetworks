"""
 Copyright (c) 2025 Computer Networks Group @ UPB

 Permission is hereby granted, free of charge, to any person obtaining a copy of
 this software and associated documentation files (the "Software"), to deal in
 the Software without restriction, including without limitation the rights to
 use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 the Software, and to permit persons to whom the Software is furnished to do so,
 subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 """

from lib.gen import GenInts, GenMultipleOfInRange
from lib.test import CreateTestData, RunIntTest
from lib.worker import *
from scapy.all import Packet, bind_layers, get_if_hwaddr, get_if_list, srp1, sendp
from scapy.fields import IntField, ShortField, FieldListField, ByteField
from scapy.layers.l2 import Ether
import time

NUM_ITER   = 1     # TODO: Make sure your program can handle larger values
CHUNK_SIZE = 4  # TODO: Define me

SWITCHML_ETHERTYPE = 0x88F0 

class SwitchML(Packet):
    name = "SwitchMLPacket"
    fields_desc = [
        ShortField("allreduce_id", 0),    # 2 Byte Unique ID for the all-reduce operation
        ShortField("chunk_idx", 0),       # 2 Byte Index of the chunk in the all-reduce operation
        ShortField("num_chunks", 0),      # 2 Byte Total number of chunks in the all-reduce operation
        ByteField("worker_rank", 0)       # 1 Byte Rank of the worker sending this packet
    ]
 
# Bind the custom SwitchML layer to Ethernet with the custom ethertype
bind_layers(Ether, SwitchML, type=SWITCHML_ETHERTYPE) # SwitchML follows the Ether Layer when the ether type is oue defined switch ehtertype

def AllReduce(iface, rank, data, result):
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
    current_allreduce_id = epoch # Assign unique id to each operation
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

        raw_chunk_payload = struct.pack('!' + 'I' * CHUNK_SIZE, *chunk_data)
        Log("Raw chunk payload: %s" % raw_chunk_payload) # Converts python data into byte object according to network format

        dst_mac_of_switch = 'ff:ff:ff:ff:ff:ff'

        try:
            eth_frame = Ether(dst=dst_mac_of_switch,
                              src=get_if_hwaddr(iface),  # Use the MAC address of the interface
                              type=SWITCHML_ETHERTYPE
                             ) / SwitchMLPacket / raw_chunk_payload # Creating an ether packet with different layers, ethernet, SwitchML and actual payload

            Log("Crafted Ethernet frame: %s" % eth_frame.show(dump=True))
 
            # Only wait for response on the last chunk
            response_pkt = srp1(        # Send raw packet and wait for 1 response, if no response response_pkt will be none
                eth_frame,
                iface=iface,
                timeout=10,  # time out for debugging purposes
                verbose=0
            )
            time.sleep(0.05)  # Delay for 50ms to give the switch time to process

        except Exception as e:
            Log("Error sending packet: %s" % str(e))
            exit(1)
        
        if response_pkt and response_pkt.haslayer(SwitchML):
            
            payload_bytes = bytes(response_pkt[SwitchML].payload)
            
            if len(payload_bytes) >= 4:         # Checking for atleast 1 32 bit value
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

def GetRankOrExit():
	rank = int(sys.argv[1])
	if rank == None or rank < 0:
		sys.exit()
		return 0
	else:
		return rank

def main():
    iface = 'eth0'
    rank = GetRankOrExit()
    Log("Started...")
    for i in range(NUM_ITER):
        num_elem = GenMultipleOfInRange(2, 2048, 2 * CHUNK_SIZE) # You may want to 'fix' num_elem for debugging
        data_out = GenInts(num_elem)
        data_in = GenInts(num_elem, 0)
        CreateTestData("eth-iter-%d" % i, rank, data_out)
        AllReduce(iface, rank, data_out, data_in)
        RunIntTest("eth-iter-%d" % i, rank, data_in, True)
    Log("Done")

if __name__ == '__main__':
    main()
