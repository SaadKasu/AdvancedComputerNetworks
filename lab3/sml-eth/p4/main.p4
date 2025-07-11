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

const bit<16> ETH_TYPE_SWITCHML = 0x1234;
const bit<16> CHUNK_SIZE = 512;

// Ethernet header struct
header ethernet_t {
    mac_addr_t dstAddr;
    mac_addr_t srcAddr;
    bit<16>   etherType;
}

header data {
    bit<32> value;
}

header sml_t {
    bit<32> chunk_count; 
    bit<32> chunk_size;
}

// Headers struct
struct headers {
  ethernet_t eth;
  sml_t sml;
  data[512] data_chunk;
}

struct metadata { /* empty */ }

parser TheParser(packet_in packet,
                 out headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
  /* TODO: Implement me */

   // Start state
  state start {
    transition parse_ethernet;
  }
  
  // State for parsing Ethernet header 
  state parse_ethernet {
  
    packet.extract(hdr.eth);
    transition parse_switchml;
  }
  
  state parse_switchml {
  	packet.extract(hdr.sml);
  	transition accept;
  }
}

control TheIngress(inout headers hdr,
                   inout metadata meta,
                   inout standard_metadata_t standard_metadata) {

  register<bit<32>>(1024) aggregate;
  
  action drop() {
    mark_to_drop(standard_metadata);
  }

  @atomic
  action aggregate_chunks(){
 	
 	    bit<32> sum;
        aggregate.read(sum, 0);
        aggregate.write(0, sum + 5);
  }

  // Simple L2 forwarding action
  action l2_forward(sw_port_t port) {
    standard_metadata.egress_spec = port;
  }

  // Multicast action; for ARP requests
  action multicast(bit<16> mgid) {
    standard_metadata.mcast_grp = mgid;
  }

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


  apply {

    if (hdr.eth.isValid() && hdr.sml.isValid()) {
    
      ethernet_table.apply();
    } else {
      drop();
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
