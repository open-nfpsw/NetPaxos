#include "headers.p4"

header_type local_metadata_t {
    fields {
        rnd : RND_SIZE;
    }
}


header ethernet_t ethernet;
header ipv4_t ipv4;
header udp_t udp;
header paxos_t paxos;
metadata local_metadata_t local_metadata;

#define ETHERTYPE_IPV4 0x0800
#define UDP_PROTOCOL 0x11
#define PAXOS_PROTOCOL 0x8888

parser start {
    return parse_ethernet;
}

parser parse_ethernet {
    extract(ethernet);
    return select(latest.etherType) {
        ETHERTYPE_IPV4 : parse_ipv4; 
        default : ingress;
    }
}

parser parse_ipv4 {
    extract(ipv4);
    return select(latest.protocol) {
        UDP_PROTOCOL : parse_udp;
        default : ingress;
    }
}

parser parse_udp {
    extract(udp);
    return select(udp.dstPort) {
        PAXOS_PROTOCOL: parse_paxos;
        default: ingress;
    }
}

parser parse_paxos {
    extract(paxos);
    set_metadata(local_metadata.rnd, latest.rnd);
    return ingress;
}

register acceptor_id {
    width: ACPT_SIZE;
    instance_count : 1; 
}

register rnd_register {
    width : RND_SIZE;
    instance_count : INST_COUNT;
}

register vrnd_register {
    width : RND_SIZE;
    instance_count : INST_COUNT;
}

register val_register {
    width : VALUE_SIZE;
    instance_count : INST_COUNT;
}

primitive_action get_forwarding_start_time();
primitive_action get_forwarding_end_time();
primitive_action get_acceptor_start_time();
primitive_action get_acceptor_end_time();


action forward(port) {
    get_forwarding_start_time();
    modify_field(standard_metadata.egress_spec, port);
    get_forwarding_end_time();
}

table fwd_tbl {
    reads {
        standard_metadata.ingress_port : exact;
    }
    actions {
        forward;
        _drop;
    }
    size : 8;
}

action _no_op() {
}

action _drop() {
    drop();
}

action read_round() {
    register_read(local_metadata.rnd, rnd_register, paxos.inst); 
}

table round_tbl {
    actions { read_round; }
    size : 1;
}


action handle_phase1a() {
    // paxos_phase1a();
    register_write(rnd_register, paxos.inst, paxos.rnd);
    register_read(paxos.acpt, acceptor_id, 0);
    modify_field(udp.checksum, 0);
}

action handle_phase2a() {
    get_acceptor_start_time();
    register_write(rnd_register, paxos.inst, paxos.rnd);
    register_write(vrnd_register, paxos.inst, paxos.rnd);
    register_write(val_register, paxos.inst, paxos.val);
    modify_field(paxos.msgtype, PHASE_2B);
    register_read(paxos.acpt, acceptor_id, 0);
    get_acceptor_end_time();
    modify_field(udp.checksum, 0);
}

table paxos_tbl {
    reads {
        paxos.msgtype : exact;
    }
    actions {
        handle_phase1a;
        handle_phase2a;
        _no_op;
    }
    size : 8;
}

control ingress {
    if (valid (ipv4)) {
        apply(fwd_tbl);
    }
    if (valid (paxos)) {
        apply(round_tbl);
        if (local_metadata.rnd <= paxos.rnd) {
            apply(paxos_tbl);
        }
    }
}