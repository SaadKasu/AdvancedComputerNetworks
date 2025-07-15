/*
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
 */
#include <core.p4>
#include <v1model.p4>
 
typedef bit<9>  sw_port_t;   /*< Switch port */
typedef bit<48> mac_addr_t;  /*< MAC address */
 
// Custom Ethetype for SwitchML protocol
const bit<16> SWITCHML_ETHERTYPE = 0x88F0;
 
 
// Number of workers (N)
const int N_WORKERS = 2;
 
// Max chunk size (C) 
const int C_CHUNK_SIZE = 4;
 
// Assuming max vec length  of 2048 with CHUNK_SIZE = 2
// max chunks = 1024 i.e 2048 / Chunk_SIZE
const int MAX_CHUNKS_IN_VECTOR = 1024;
 
// Register to store the aggregated sum for each element in a chunk
register<bit<32>>(MAX_CHUNKS_IN_VECTOR * C_CHUNK_SIZE) aggregation_values;
 
// should be modified according to C_CHUNK_SIZE
register<bit<4>>(MAX_CHUNKS_IN_VECTOR) chunk_contributions;
 
// Register to store the last AllReduce ID processed for each chunk.
// To enable reuse of memory and updating aggregations
register<bit<16>>(MAX_CHUNKS_IN_VECTOR) last_allreduce_id;
 
// Standard headers
header ethernet_t {
  /* TODO: Define me */
  mac_addr_t dstAddr;
  mac_addr_t srcAddr;
  bit<16> etherType; 
}
 
// header for the chunk payload data: 32 bit fields
// varies according to our CHUNK_SIZE = 2
// Increasing CHUNK_SIZE = 4, we can have val0 to val3
header chunk_data_t {
  bit<32> val0;
  bit<32> val1;
  bit<32> val2;
  bit<32> val3;
}
 
// Custom header for SwitchML protocol
// mirrors the structure of the SwitchMLPacket in our worker.py
header sml_t {
  /* TODO: Define me */
  bit<16> allreduce_id;
  bit<16> chunk_idx;
  bit<16> num_chunks;
  bit<8>  worker_rank;
}
 
struct headers {
  ethernet_t eth;
  sml_t sml;
  chunk_data_t chunk_data;
}
 
struct metadata { /* empty */ }
 
parser TheParser(packet_in packet,
                 out headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
  /* TODO: Implement me */
  state start {
    packet.extract(hdr.eth);
    transition select(hdr.eth.etherType) {
      0x88F0: parse_sml; // SwitchML Ethertype
      default: accept;  // Drop or process other packerts
                        // for L1: Ipv4 we can just drop 
    }
  }
 
  state parse_sml {
    packet.extract(hdr.sml);
    // After the customer switchML header we parse the chunk data
    packet.extract(hdr.chunk_data);
    transition accept; 
  }
}
 
control TheIngress(inout headers hdr,
                   inout metadata meta,
                   inout standard_metadata_t standard_metadata) {
  
  // Multicast group for broadcasting
  const bit<16> ALL_WORKERS_MCAST_GROUP = 1;
  
  // Temporal variables to hold register values during atomic access
  bit<32> current_val0 = 0;
  bit<32> current_val1 = 0;
  bit<32> current_val2 = 0;
  bit<32> current_val3 = 0; // values will be added with incrasing C_CHUNK_SIZE
  
  bit<4> current_contribution_mask; // Use 2 because N_WORKERS = 2
  bit<16> current_allreduce_id;
  
  
  apply {
    /* TODO: Implement me */
    // Only process packets with SwitchML Ethertype
    if (hdr.sml.isValid()) {
      // Compute the base index for the current chunk
      bit<32> base_agg_index = (bit<32>)hdr.sml.chunk_idx * C_CHUNK_SIZE;
 
      // ---- Handle AllReduce ID and chunk contribution Tracking ----
      @atomic { // Atomc access for registers
        // read current allReduce id for chunk index
        last_allreduce_id.read(current_allreduce_id, (bit<32>)hdr.sml.chunk_idx);
        // read current contribution mask for the chunk index
        chunk_contributions.read(current_contribution_mask, (bit<32>)hdr.sml.chunk_idx);
      }
 
      // Check if this is a new AllReduce operation for this chunk index or retransmission
      // For L1, we assume reliability so every id is a new AllReduce
      // L3, we will redesign the logic
 
      // L1: we aggregate if the the worker has not contributed to this chunk
      // and we re-initialize if its a new AllReduce ID
 
      // if current_allreduce_id is different, or if workers has not contributed
      if (current_allreduce_id != hdr.sml.allreduce_id ||
          (current_contribution_mask & ((bit<4>)(1) << hdr.sml.worker_rank)) == 0) { // check if worker bit isset
        
        // For a new AllReduce ID for this chunk reset the mask and agg values
        if(current_allreduce_id != hdr.sml.allreduce_id) {
          current_contribution_mask = 0;
          // we could also clear agg values
          // We can also clear them in egreess
        }
 
        // read current aggregation values
 
        @atomic { // We simply separate the blocks for the different register arrays
          aggregation_values.read(current_val0, base_agg_index);
          aggregation_values.read(current_val1, base_agg_index + 1);
          aggregation_values.read(current_val2, base_agg_index + 2);
          aggregation_values.read(current_val3, base_agg_index + 3);
          // Based on ChUNK_SIZE, we can have more values here
        }
        
        // Perform the aggregation (Addition for AllReduce SUM)
        current_val0 = current_val0 + hdr.chunk_data.val0;
        current_val1 = current_val1 + hdr.chunk_data.val1;
        current_val2 = current_val2 + hdr.chunk_data.val2;
        current_val3 = current_val3 + hdr.chunk_data.val3;
        // More agreegation with increasing C_CHUNK_SIZE
 
        // Update the contribution mask to include this worker
        // update the worker's bit in the mask
        current_contribution_mask = current_contribution_mask | ((bit<4>)(1) << hdr.sml.worker_rank); // Set worker's bit
 
        @atomic {
          aggregation_values.write(base_agg_index, current_val0);
          aggregation_values.write(base_agg_index + 1, current_val1);
          aggregation_values.write(base_agg_index + 2, current_val2);
          aggregation_values.write(base_agg_index + 3, current_val3);
          // More agreegation updates increasing C_CHUNK_SIZE
 
          chunk_contributions.write((bit<32>)hdr.sml.chunk_idx, current_contribution_mask);
          last_allreduce_id.write((bit<32>)hdr.sml.chunk_idx, hdr.sml.allreduce_id);
        }
      }
      // if it is a retransmission,(bit already set for current_allreduce_id)
      // check if all workers have contributed for this chunk
      if (current_contribution_mask == (1 << N_WORKERS) - 1) { // all masks are 1
        
        // multicast the packet to all the workers
        standard_metadata.mcast_grp = ALL_WORKERS_MCAST_GROUP;
 
        // for L1, the packet should contain aggregation
        // L3, the switch should store and retrieve it
        hdr.chunk_data.val0 = current_val0;
        hdr.chunk_data.val1 = current_val1;
        hdr.chunk_data.val2 = current_val2;
        hdr.chunk_data.val3 = current_val3;
        // More aggregation with increasing C_CHUNK_SIZE
 
      } else {
        // Not all workers have contributed yet, so we drop the packet
        mark_to_drop(standard_metadata);
      }
    }else{
      // Not our protocol n this case, we may drop
      mark_to_drop(standard_metadata);
    }
  }
}
 
control TheEgress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
  apply {
    /* TODO: Implement me (if needed) */
    // we may need to clear the memory for reuse here
    // however, we cannot clear if we have not yet gottent the last contributions
    // We could define a variable which is set to true when the last AllReduce is made
    // then we can test for that variable and clear memory
 
    // Assumption: setting current_all_reduce_id in ingress is sufficient
  }
}
 
control TheChecksumVerification(inout headers hdr, inout metadata meta) {
  apply {
    /* TODO: Implement me (if needed) */
  }
}
 
control TheChecksumComputation(inout headers  hdr, inout metadata meta) {
  apply {
    /* TODO: Implement me (if needed) */
  }
}
 
control TheDeparser(packet_out packet, in headers hdr) {
  apply {
    /* TODO: Implement me */
    packet.emit(hdr.eth);
    // only emit our SwitchML and chunk_data assuming they are valid
    // if an aggregation occured, the packet is forwarded
    packet.emit(hdr.sml);
    packet.emit(hdr.chunk_data);
  } 
}
 
V1Switch(
  TheParser(),
  TheChecksumVerification(),
  TheIngress(),
  TheEgress(),
  TheChecksumComputation(),
  TheDeparser()
) main;
