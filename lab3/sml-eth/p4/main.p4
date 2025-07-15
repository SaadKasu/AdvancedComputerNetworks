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
const int C_CHUNK_SIZE = 8;

// Assuming max vec length of 2048 with CHUNK_SIZE = 8
const int MAX_CHUNKS_IN_VECTOR = 256;

// Register to store the aggregated sum for each element in a chunk
register<bit<32>>(MAX_CHUNKS_IN_VECTOR * C_CHUNK_SIZE) aggregation_values;

// Contribution tracking
register<bit<4>>(MAX_CHUNKS_IN_VECTOR) chunk_contributions;

// Last AllReduce ID per chunk
register<bit<16>>(MAX_CHUNKS_IN_VECTOR) last_allreduce_id;

// Ethernet header
header ethernet_t {
  mac_addr_t dstAddr;
  mac_addr_t srcAddr;
  bit<16> etherType;
}

// Chunk data (CHUNK_SIZE = 8)
header chunk_data_t {
  bit<32> val0;
  bit<32> val1;
  bit<32> val2;
  bit<32> val3;
  bit<32> val4;
  bit<32> val5;
  bit<32> val6;
  bit<32> val7;
}

// SwitchML header
header sml_t {
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

struct metadata {}

parser TheParser(packet_in packet, out headers hdr,
                 inout metadata meta, inout standard_metadata_t smeta) {
  state start {
    packet.extract(hdr.eth);
    transition select(hdr.eth.etherType) {
      0x88F0: parse_sml;
      default: accept;
    }
  }

  state parse_sml {
    packet.extract(hdr.sml);
    packet.extract(hdr.chunk_data);
    transition accept;
  }
}

control TheIngress(inout headers hdr, inout metadata meta, inout standard_metadata_t smeta) {
  const bit<16> ALL_WORKERS_MCAST_GROUP = 1;

  bit<32> current_val0 = 0;
  bit<32> current_val1 = 0;
  bit<32> current_val2 = 0;
  bit<32> current_val3 = 0;
  bit<32> current_val4 = 0;
  bit<32> current_val5 = 0;
  bit<32> current_val6 = 0;
  bit<32> current_val7 = 0;

  bit<4> current_contribution_mask;
  bit<16> current_allreduce_id;

  apply {
    if (hdr.sml.isValid()) {
      bit<32> base_idx = (bit<32>)hdr.sml.chunk_idx * C_CHUNK_SIZE;

      @atomic {
        last_allreduce_id.read(current_allreduce_id, (bit<32>)hdr.sml.chunk_idx);
        chunk_contributions.read(current_contribution_mask, (bit<32>)hdr.sml.chunk_idx);
      }

      if (current_allreduce_id != hdr.sml.allreduce_id ||
          (current_contribution_mask & ((bit<4>)(1) << hdr.sml.worker_rank)) == 0) {

        if (current_allreduce_id != hdr.sml.allreduce_id) {
          current_contribution_mask = 0;
            @atomic {
                aggregation_values.write(base_idx, 0);
                aggregation_values.write(base_idx + 1, 0);
                aggregation_values.write(base_idx + 2, 0);
                aggregation_values.write(base_idx + 3, 0);
                aggregation_values.write(base_idx + 4, 0);
                aggregation_values.write(base_idx + 5, 0);
                aggregation_values.write(base_idx + 6, 0);
                aggregation_values.write(base_idx + 7, 0);
              }
        }

        @atomic {
          aggregation_values.read(current_val0, base_idx);
          aggregation_values.read(current_val1, base_idx + 1);
          aggregation_values.read(current_val2, base_idx + 2);
          aggregation_values.read(current_val3, base_idx + 3);
          aggregation_values.read(current_val4, base_idx + 4);
          aggregation_values.read(current_val5, base_idx + 5);
          aggregation_values.read(current_val6, base_idx + 6);
          aggregation_values.read(current_val7, base_idx + 7);
        }

        current_val0 = current_val0 + hdr.chunk_data.val0;
        current_val1 = current_val1 + hdr.chunk_data.val1;
        current_val2 = current_val2 + hdr.chunk_data.val2;
        current_val3 = current_val3 + hdr.chunk_data.val3;
        current_val4 = current_val4 + hdr.chunk_data.val4;
        current_val5 = current_val5 + hdr.chunk_data.val5;
        current_val6 = current_val6 + hdr.chunk_data.val6;
        current_val7 = current_val7 + hdr.chunk_data.val7;

        current_contribution_mask = current_contribution_mask | ((bit<4>)(1) << hdr.sml.worker_rank);

        @atomic {
          aggregation_values.write(base_idx, current_val0);
          aggregation_values.write(base_idx + 1, current_val1);
          aggregation_values.write(base_idx + 2, current_val2);
          aggregation_values.write(base_idx + 3, current_val3);
          aggregation_values.write(base_idx + 4, current_val4);
          aggregation_values.write(base_idx + 5, current_val5);
          aggregation_values.write(base_idx + 6, current_val6);
          aggregation_values.write(base_idx + 7, current_val7);

          chunk_contributions.write((bit<32>)hdr.sml.chunk_idx, current_contribution_mask);
          last_allreduce_id.write((bit<32>)hdr.sml.chunk_idx, hdr.sml.allreduce_id);
        }
      }

      if (current_contribution_mask == (1 << N_WORKERS) - 1) {
        smeta.mcast_grp = ALL_WORKERS_MCAST_GROUP;

        hdr.chunk_data.val0 = current_val0;
        hdr.chunk_data.val1 = current_val1;
        hdr.chunk_data.val2 = current_val2;
        hdr.chunk_data.val3 = current_val3;
        hdr.chunk_data.val4 = current_val4;
        hdr.chunk_data.val5 = current_val5;
        hdr.chunk_data.val6 = current_val6;
        hdr.chunk_data.val7 = current_val7;
      } else {
        mark_to_drop(smeta);
      }
    } else {
      mark_to_drop(smeta);
    }
  }
}

control TheEgress(inout headers hdr, inout metadata meta, inout standard_metadata_t smeta) {
  apply { }
}

control TheChecksumVerification(inout headers hdr, inout metadata meta) {
  apply { }
}

control TheChecksumComputation(inout headers hdr, inout metadata meta) {
  apply { }
}

control TheDeparser(packet_out packet, in headers hdr) {
  apply {
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
