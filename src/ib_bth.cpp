/*
 * Copyright (c) 2022, Cerebras Systems
 * All rights reserved.
 *
 */

//#include <cstring>
#include <cassert>
#include <tins/ib_bth.h>
//#include <tins/constants.h>
//#include <tins/ip.h>
//#include <tins/ipv6.h>
#include <tins/rawpdu.h>
//#include <tins/exceptions.h>
#include <tins/memory_helpers.h>
//#include <tins/utils/checksum_utils.h>

using Tins::Memory::PduInputMemoryStream;
using Tins::Memory::OutputMemoryStream;

namespace Tins {
namespace IB {

// TODO List
//============================================================================
// [ ] padcnt:
//     * It should be filled in automatically when serializing.
//     * It should be used when reading from buffer to prevent the pad
//       from being part of the constructed inner_pdu.


/* Packet content flags. */
enum PacketContents {
    RDETH = 1 << 0,
    DETH = 1 << 1,
    RETH = 1 << 2,
    ATETH = 1 << 3,
    AETH = 1 << 4,
    ATAETH = 1 << 5,
    IMMDT = 1 << 6,
    IETH = 1 << 7,
    XRCETH = 1 << 8,
    PAYLOAD = 1 << 9,
};

/* Map from opcode to packet content flags. */
static const std::map<Opcodes, int> opcode_packet_contents_map = {
    /* Reliable Connection (RC) */
    {RC_SEND_FIRST,                 PAYLOAD},
    {RC_SEND_MIDDLE,                PAYLOAD},
    {RC_SEND_LAST,                  PAYLOAD},
    {RC_SEND_LAST_IMM,              IMMDT | PAYLOAD},
    {RC_SEND_ONLY,                  PAYLOAD},
    {RC_SEND_ONLY_IMM,              IMMDT | PAYLOAD},
    {RC_RDMA_WRITE_FIRST,           RETH | PAYLOAD},
    {RC_RDMA_WRITE_MIDDLE,          PAYLOAD},
    {RC_RDMA_WRITE_LAST,            PAYLOAD},
    {RC_RDMA_WRITE_LAST_IMM,        IMMDT | PAYLOAD},
    {RC_RDMA_WRITE_ONLY,            RETH | PAYLOAD},
    {RC_RDMA_WRITE_ONLY_IMM,        RETH | IMMDT | PAYLOAD},
    {RC_RDMA_READ_REQUEST,          RETH},
    {RC_RDMA_READ_RESPONSE_FIRST,   AETH | PAYLOAD},
    {RC_RDMA_READ_RESPONSE_MIDDLE,  PAYLOAD},
    {RC_RDMA_READ_RESPONSE_LAST,    AETH | PAYLOAD},
    {RC_RDMA_READ_RESPONSE_ONLY,    AETH | PAYLOAD},
    {RC_ACKNOWLEDGE,                AETH},
    {RC_ATOMIC_ACKNOWLEDGE,         AETH | ATAETH},
    {RC_CMP_SWAP,                   ATETH},
    {RC_FETCH_ADD,                  ATETH},
    {RC_SEND_LAST_INVAL,            IETH | PAYLOAD},
    {RC_SEND_ONLY_INVAL,            IETH | PAYLOAD},
        
    /* Unreliable Connection (UC) */
    {UC_SEND_FIRST,                 PAYLOAD},
    {UC_SEND_MIDDLE,                PAYLOAD},
    {UC_SEND_LAST,                  PAYLOAD},
    {UC_SEND_LAST_IMM,              IMMDT | PAYLOAD},
    {UC_SEND_ONLY,                  PAYLOAD},
    {UC_SEND_ONLY_IMM,              IMMDT | PAYLOAD},
    {UC_RDMA_WRITE_FIRST,           RETH | PAYLOAD},
    {UC_RDMA_WRITE_MIDDLE,          PAYLOAD},
    {UC_RDMA_WRITE_LAST,            PAYLOAD},
    {UC_RDMA_WRITE_LAST_IMM,        IMMDT | PAYLOAD},
    {UC_RDMA_WRITE_ONLY,            RETH | PAYLOAD},
    {UC_RDMA_WRITE_ONLY_IMM,        RETH | IMMDT | PAYLOAD},
        
    /* Reliable Datagram (RD) */
    {RD_SEND_FIRST,                 RDETH | DETH | PAYLOAD},
    {RD_SEND_MIDDLE,                RDETH | DETH | PAYLOAD},
    {RD_SEND_LAST,                  RDETH | DETH | PAYLOAD},
    {RD_SEND_LAST_IMM,              RDETH | DETH | IMMDT | PAYLOAD},
    {RD_SEND_ONLY,                  RDETH | DETH | PAYLOAD},
    {RD_SEND_ONLY_IMM,              RDETH | DETH | IMMDT | PAYLOAD},
    {RD_RDMA_WRITE_FIRST,           RDETH | DETH | RETH | PAYLOAD},
    {RD_RDMA_WRITE_MIDDLE,          RDETH | DETH | PAYLOAD},
    {RD_RDMA_WRITE_LAST,            RDETH | DETH | PAYLOAD},
    {RD_RDMA_WRITE_LAST_IMM,        RDETH | DETH | IMMDT | PAYLOAD},
    {RD_RDMA_WRITE_ONLY,            RDETH | DETH | RETH | PAYLOAD},
    {RD_RDMA_WRITE_ONLY_IMM,        RDETH | DETH | RETH | IMMDT | PAYLOAD},
    {RD_RDMA_READ_REQUEST,          RDETH | DETH | RETH},
    {RD_RDMA_READ_RESPONSE_FIRST,   RDETH | AETH | PAYLOAD},
    {RD_RDMA_READ_RESPONSE_MIDDLE,  RDETH | PAYLOAD},
    {RD_RDMA_READ_RESPONSE_LAST,    RDETH | AETH | PAYLOAD},
    {RD_RDMA_READ_RESPONSE_ONLY,    RDETH | AETH | PAYLOAD},
    {RD_ACKNOWLEDGE,                RDETH | AETH},
    {RD_ATOMIC_ACKNOWLEDGE,         RDETH | AETH | ATAETH},
    {RD_CMP_SWAP,                   RDETH | DETH | ATETH},
    {RD_FETCH_ADD,                  RDETH | DETH | ATETH},
    {RD_RESYNC,                     RDETH | DETH},
        
    /* Unreliable Datagram (UD) */
    {UD_SEND_ONLY,                  DETH | PAYLOAD},
    {UD_SEND_ONLY_IMM,              DETH | IMMDT | PAYLOAD},
        
    /* CNP */
    {CNP,                           0},

    /* Extended Reliable Connection (XRC) */
    {XRC_SEND_FIRST,                XRCETH | PAYLOAD},
    {XRC_SEND_MIDDLE,               XRCETH | PAYLOAD},
    {XRC_SEND_LAST,                 XRCETH | PAYLOAD},
    {XRC_SEND_LAST_IMM,             XRCETH | IMMDT | PAYLOAD},
    {XRC_SEND_ONLY,                 XRCETH | PAYLOAD},
    {XRC_SEND_ONLY_IMM,             XRCETH | IMMDT | PAYLOAD},
    {XRC_RDMA_WRITE_FIRST,          XRCETH | RETH | PAYLOAD},
    {XRC_RDMA_WRITE_MIDDLE,         XRCETH | PAYLOAD},
    {XRC_RDMA_WRITE_LAST,           XRCETH | PAYLOAD},
    {XRC_RDMA_WRITE_LAST_IMM,       XRCETH | IMMDT | PAYLOAD},
    {XRC_RDMA_WRITE_ONLY,           XRCETH | RETH | PAYLOAD},
    {XRC_RDMA_WRITE_ONLY_IMM,       XRCETH | RETH | IMMDT | PAYLOAD},
    {XRC_RDMA_READ_REQUEST,         XRCETH | RETH},
    {XRC_RDMA_READ_RESPONSE_FIRST,  AETH | PAYLOAD},
    {XRC_RDMA_READ_RESPONSE_MIDDLE, PAYLOAD},
    {XRC_RDMA_READ_RESPONSE_LAST,   AETH | PAYLOAD},
    {XRC_RDMA_READ_RESPONSE_ONLY,   AETH | PAYLOAD},
    {XRC_ACKNOWLEDGE,               AETH},
    {XRC_ATOMIC_ACKNOWLEDGE,        AETH | ATAETH},
    {XRC_CMP_SWAP,                  XRCETH | ATETH},
    {XRC_FETCH_ADD,                 XRCETH | ATETH},
    {XRC_SEND_LAST_INVAL,           XRCETH | IETH | PAYLOAD},
    {XRC_SEND_ONLY_INVAL,           XRCETH | IETH | PAYLOAD},
};

PDU::metadata BTH::extract_metadata(const uint8_t* buffer, uint32_t total_sz) {
    if (TINS_UNLIKELY(total_sz < sizeof(bth_header))) {
        throw malformed_packet();
    }
    
    const bth_header* header = reinterpret_cast<const bth_header*>(buffer);
    uint32_t header_size =
        header_size_from_opcode(static_cast<Opcodes>(header->opcode));
    if (TINS_UNLIKELY(total_sz < header_size)) {
        throw malformed_packet();
    }
    
    //XXX How is ICRC factored in? Pad? Should pad be added into trailer_size?
    
    return metadata(header_size, pdu_flag, PDU::UNKNOWN);
}

BTH::BTH(Opcodes new_opcode) {
    opcode(new_opcode);
    tver(0);
}

BTH::BTH(const uint8_t* buffer, uint32_t total_sz) {
    PduInputMemoryStream stream(this, buffer, total_sz);
    stream.read(header_);
    update_packet_contents();

    /* Make sure that we have enough size for all headers and ICRC and
     * that there are no extra bytes if a payload is not expected. */
    if (TINS_UNLIKELY(
            (total_sz < header_size() + trailer_size()) ||
            (!has_payload_ && total_sz > header_size() + trailer_size()))) {
        malformed(true);
        return;
    }
    
    /* This relies on the fact that the relative order of extended
     * headers is the same across all opcodes. For example, if there
     * is an AETH, it always comes after an RDETH. Some have arbitrary
     * relative order because they never occur together in the same
     * packet, such as IETH and ImmDt. If this were not true, then
     * this code would need to be dependent on opcode and would be
     * much longer. */
    if (has_rdeth_)  stream.read(rdeth_);
    if (has_deth_)   stream.read(deth_);
    if (has_xrceth_) stream.read(xrceth_);
    if (has_reth_)   stream.read(reth_);
    if (has_aeth_)   stream.read(aeth_);
    if (has_ateth_)  stream.read(ateth_);
    if (has_ataeth_) stream.read(ataeth_);
    if (has_immdt_)  stream.read(immdt_);
    if (has_ieth_)   stream.read(ieth_);
    
    //XXX Is a zero-length payload legal for an opcode that has a payload?
    uint32_t payload_size = stream.size() - trailer_size();
    if (TINS_UNLIKELY(payload_size % 4 != 0)) {
        malformed(true);
        return;
    }
    
    if (payload_size) {
        /* Don't include the pad in the innerPDU, but still use it in 
         * the skip. */
        inner_pdu(new RawPDU(stream.pointer(), payload_size - padcnt()));
        stream.skip(payload_size);
    }
    
    assert(stream.size() == trailer_size());
    stream.read(icrc_);
}

uint32_t BTH::header_size() const {
    uint32_t sum = sizeof(bth_header);
    if (has_rdeth_)  sum += sizeof(rdeth_header);
    if (has_deth_)   sum += sizeof(deth_header);
    if (has_reth_)   sum += sizeof(reth_header);
    if (has_ateth_)  sum += sizeof(ateth_header);
    if (has_aeth_)   sum += sizeof(aeth_header);
    if (has_ataeth_) sum += sizeof(ataeth_header);
    if (has_immdt_)  sum += sizeof(immdt_header);
    if (has_ieth_)   sum += sizeof(ieth_header);
    if (has_xrceth_) sum += sizeof(xrceth_header);

    return sum;
}

uint32_t BTH::trailer_size() const {
    /* ICRC is 4 bytes and is always present after the payload or
     * the last header. */
    //XXX See EthernetII::trailer_size() for an example of how to
    //XXX factor in a variable pad size.
    return 4;
}

//XXX Consider moving these to endianness.h
static void be_to_host24(const uint8_t* src_bytes, uint32_t* dst_word) {
    uint8_t* dst_bytes = reinterpret_cast<uint8_t*>(dst_word);
    
    #if TINS_IS_LITTLE_ENDIAN
    dst_bytes[3] = 0;
    dst_bytes[2] = src_bytes[0];
    dst_bytes[1] = src_bytes[1];
    dst_bytes[0] = src_bytes[2];
    #else
    dst_bytes[0] = 0;
    dst_bytes[1] = src_bytes[0];
    dst_bytes[2] = src_bytes[1];
    dst_bytes[3] = src_bytes[2];
    #endif
}

static void host_to_be24(const uint32_t* src_word, uint8_t* dst_bytes) {
    assert(src_word & 0xff000000 == 0);
    const uint8_t* src_bytes = reinterpret_cast<const uint8_t*>(src_word);

    #if TINS_IS_LITTLE_ENDIAN
    dst_bytes[0] = src_bytes[2];
    dst_bytes[1] = src_bytes[1];
    dst_bytes[2] = src_bytes[0];
    #else
    dst_bytes[0] = src_bytes[1];
    dst_bytes[1] = src_bytes[2];
    dst_bytes[2] = src_bytes[3];
    #endif
}

small_uint<24> BTH::destqp() const {
    uint32_t destqp;
    be_to_host24(header_.destqp, &destqp);
    return destqp;
}

small_uint<24> BTH::psn() const {
    uint32_t psn;
    be_to_host24(header_.psn, &psn);
    return psn;
}

void BTH::opcode(Opcodes new_opcode) {
    header_.opcode = new_opcode;
    update_packet_contents();
}

void BTH::destqp(small_uint<24> new_destqp) {
    uint32_t destqp = new_destqp;
    host_to_be24(&destqp, header_.destqp);
}

void BTH::psn(small_uint<24> new_psn) {
    uint32_t psn = new_psn;
    host_to_be24(&psn, header_.psn);
}

small_uint<24> BTH::ee() const {
    if (!has_rdeth_) throw field_not_present();

    uint32_t ee;
    be_to_host24(rdeth_.ee, &ee);
    return ee;
}
    
void BTH::ee(small_uint<24> new_ee) {
    if (!has_rdeth_) throw field_not_present();

    uint32_t ee = new_ee;
    host_to_be24(&ee, rdeth_.ee);
}

small_uint<24> BTH::srcqp() const {
    if (!has_deth_) throw field_not_present();

    uint32_t srcqp;
    be_to_host24(deth_.srcqp, &srcqp);
    return srcqp;
}
    
void BTH::srcqp(small_uint<24> new_srcqp) {
    if (!has_deth_) throw field_not_present();

    uint32_t srcqp = new_srcqp;
    host_to_be24(&srcqp, deth_.srcqp);
}

small_uint<24> BTH::msn() const {
    if (!has_aeth_) throw field_not_present();

    uint32_t msn;
    be_to_host24(aeth_.msn, &msn);
    return msn;
}
    
void BTH::msn(small_uint<24> new_msn) {
    if (!has_aeth_) throw field_not_present();

    uint32_t msn = new_msn;
    host_to_be24(&msn, aeth_.msn);
}

small_uint<24> BTH::xrcsrq() const {
    if (!has_xrceth_) throw field_not_present();

    uint32_t xrcsrq;
    be_to_host24(xrceth_.xrcsrq, &xrcsrq);
    return xrcsrq;
}
    
void BTH::xrcsrq(small_uint<24> new_xrcsrq) {
    if (!has_xrceth_) throw field_not_present();

    uint32_t xrcsrq = new_xrcsrq;
    host_to_be24(&xrcsrq, xrceth_.xrcsrq);
}

uint32_t BTH::header_size_from_opcode(const Opcodes opcode) {
    int packet_contents = 0;
    try {
        packet_contents = opcode_packet_contents_map.at(opcode);
    }
    catch (std::out_of_range&) {}
    
    uint32_t sum = sizeof(bth_header);
    if (packet_contents & RDETH)  sum += sizeof(rdeth_header);
    if (packet_contents & DETH)   sum += sizeof(deth_header);
    if (packet_contents & RETH)   sum += sizeof(reth_header);
    if (packet_contents & ATETH)  sum += sizeof(ateth_header);
    if (packet_contents & AETH)   sum += sizeof(aeth_header);
    if (packet_contents & ATAETH) sum += sizeof(ataeth_header);
    if (packet_contents & IMMDT)  sum += sizeof(immdt_header);
    if (packet_contents & IETH)   sum += sizeof(ieth_header);
    if (packet_contents & XRCETH) sum += sizeof(xrceth_header);

    return sum;
}

void BTH::update_packet_contents() {
    int packet_contents = 0;
    try {
        packet_contents = opcode_packet_contents_map.at(opcode());
    }
    catch (std::out_of_range&) {}
    
    has_rdeth_   = packet_contents & RDETH;
    has_deth_    = packet_contents & DETH;
    has_reth_    = packet_contents & RETH;
    has_ateth_   = packet_contents & ATETH;
    has_aeth_    = packet_contents & AETH;
    has_ataeth_  = packet_contents & ATAETH;
    has_immdt_   = packet_contents & IMMDT;
    has_ieth_    = packet_contents & IETH;
    has_xrceth_  = packet_contents & XRCETH;
    has_payload_ = packet_contents & PAYLOAD;
}

void BTH::write_serialization(uint8_t* buffer, uint32_t total_sz) {
    OutputMemoryStream stream(buffer, total_sz);
    
    stream.write(header_);
    if (has_rdeth_)  stream.write(rdeth_);
    if (has_deth_)   stream.write(deth_);
    if (has_xrceth_) stream.write(xrceth_);
    if (has_reth_)   stream.write(reth_);
    if (has_aeth_)   stream.write(aeth_);
    if (has_ateth_)  stream.write(ateth_);
    if (has_ataeth_) stream.write(ataeth_);
    if (has_immdt_)  stream.write(immdt_);
    if (has_ieth_)   stream.write(ieth_);
    
    if (inner_pdu()) {
        stream.skip(inner_pdu()->size());
    }
    stream.write(icrc_);
}

} // IB
} // Tins
