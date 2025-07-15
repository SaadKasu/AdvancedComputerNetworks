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

const bit<16> SWITCHML_ETHERTYPE = 0x88F0;
const int C_CHUNK_SIZE = 4;
const int N_WORKERS = 2;
const int MAX_CHUNKS_IN_VECTOR = 256;

register<bit<32>>(MAX_CHUNKS_IN_VECTOR * C_CHUNK_SIZE) aggregation_values; // Array that stores 32 bit values
register<bit<4>>(MAX_CHUNKS_IN_VECTOR) chunk_contributions;
register<bit<16>>(MAX_CHUNKS_IN_VECTOR) last_allreduce_id;

// Ethernet header struct
header ethernet_t {
    mac_addr_t dstAddr;
    mac_addr_t srcAddr;
    bit<16>   etherType;
}

header chunk_data_t {
    bit<32> val0;
    bit<32> val1;
    bit<32> val2;
    bit<32> val3;
}

header sml_t {
    bit<16> allreduce_id; 
    bit<16> chunk_idx;
    bit<16> num_chunks;
    bit<8>  worker_rank;
}

// Headers struct
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

   // Start state
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

    const bit<16> ALL_WORKERS_MCAST_GROUP = 1;

    bit<32> current_sum_0 = 0;
    bit<32> current_sum_1 = 0;
    bit<32> current_sum_2 = 0;
    bit<32> current_sum_3 = 0;

    bit<4> current_contribution_mask;
    bit<16> current_allreduce_id; 

      // Ethernet forwarding table
  table ethernet_table {

    // Fields to match on and how to match
    key = {
      hdr.eth.dstAddr: exact;
    }

    // Possible actions
    actions = {
      l2_forward;
      multicast;
      drop;
      NoAction;
    }

    // Table size and default action
    size = 1024;
    default_action = NoAction();
  }

 apply{
        if(hdr.sml.isValid()){

            bit<32> base_agg_index = (bit<32>)hdr.sml.chunk_idx * C_CHUNK_SIZE;
        
            @atomic // Atomc access for registers
            { 
                last_allreduce_id.read(current_allreduce_id, (bit<32>)hdr.sml.chunk_idx);
                chunk_contributions.read(current_contribution_mask, (bit<32>)hdr.sml.chunk_idx);
            }

            if ((current_allreduce_id != hdr.sml.allreduce_id || (current_contribution_mask & ((bit<4>)(1) << hdr.sml.worker_rank)) == 0)){
                if (current_allreduce_id != hdr.sml.allreduce_id) { // check if worker bit isset
                    current_contribution_mask = 0;
                }

                @atomic 
                { // We simply separate the blocks for the different register arrays
                  aggregation_values.read(current_sum_0, base_agg_index);
                  aggregation_values.read(current_sum_1, base_agg_index + 1);
                  aggregation_values.read(current_sum_2, base_agg_index + 2);
                  aggregation_values.read(current_sum_3, base_agg_index + 3);
                  // Based on ChUNK_SIZE, we can have more values here
                }

                current_sum_0 = current_sum_0 + hdr.chunk_data.val0;
                current_sum_1 = current_sum_1 + hdr.chunk_data.val1;
                current_sum_2 = current_sum_2 + hdr.chunk_data.val2;
                current_sum_3 = current_sum_3 + hdr.chunk_data.val3;

                current_contribution_mask = current_contribution_mask | ((bit<4>)(1) << hdr.sml.worker_rank);

                @atomic {
                  aggregation_values.write(base_agg_index, current_sum_0);
                  aggregation_values.write(base_agg_index + 1, current_sum_1);
                  aggregation_values.write(base_agg_index + 2, current_sum_2);
                  aggregation_values.write(base_agg_index + 3, current_sum_3);
                  // More agreegation updates increasing C_CHUNK_SIZE
         
                  chunk_contributions.write((bit<32>)hdr.sml.chunk_idx, current_contribution_mask);
                  last_allreduce_id.write((bit<32>)hdr.sml.chunk_idx, hdr.sml.allreduce_id);
                }
            }

            if (current_contribution_mask == (1 << N_WORKERS) - 1){
                standard_metadata.mcast_grp = ALL_WORKERS_MCAST_GROUP;
                hdr.chunk_data.val0 = current_sum_0;
                hdr.chunk_data.val1 = current_sum_1;
                hdr.chunk_data.val2 = current_sum_2;
                hdr.chunk_data.val3 = current_sum_3;

            }
            else {
                mark_to_drop(standard_metadata);
            }
        }
        else{
            mark_to_drop(standard_metadata);
        }
    }
}
      

control TheEgress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
  apply {
    /* TODO: Implement me (if needed) */
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
    // Deparse the Ethernet header
    packet.emit(hdr.eth);
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
