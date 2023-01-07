/*
 * Copyright (c) 2022, Cerebras Systems
 * All rights reserved.
 *
 */

#ifndef TINS_IB_BTH_H
#define TINS_IB_BTH_H

#include <map>
#include <tins/macros.h>
#include <tins/pdu.h>
#include <tins/endianness.h>
#include <tins/small_uint.h>

namespace Tins {
namespace IB {

/**
 * \brief Infiniband transport opcodes enum.
 * 
 * Code Bits [7:5] Transport Type
 *           [4:0] Message Type
 */
enum Opcodes {
    /* Reliable Connection (RC)
     * [7:5] = 000 */
    RC_SEND_FIRST                 = 0b00000000,
    RC_SEND_MIDDLE                = 0b00000001,
    RC_SEND_LAST                  = 0b00000010,
    RC_SEND_LAST_IMM              = 0b00000011,
    RC_SEND_ONLY                  = 0b00000100,
    RC_SEND_ONLY_IMM              = 0b00000101,
    RC_RDMA_WRITE_FIRST           = 0b00000110,
    RC_RDMA_WRITE_MIDDLE          = 0b00000111,
    RC_RDMA_WRITE_LAST            = 0b00001000,
    RC_RDMA_WRITE_LAST_IMM        = 0b00001001,
    RC_RDMA_WRITE_ONLY            = 0b00001010,
    RC_RDMA_WRITE_ONLY_IMM        = 0b00001011,
    RC_RDMA_READ_REQUEST          = 0b00001100,
    RC_RDMA_READ_RESPONSE_FIRST   = 0b00001101,
    RC_RDMA_READ_RESPONSE_MIDDLE  = 0b00001110,
    RC_RDMA_READ_RESPONSE_LAST    = 0b00001111,
    RC_RDMA_READ_RESPONSE_ONLY    = 0b00010000,
    RC_ACKNOWLEDGE                = 0b00010001,
    RC_ATOMIC_ACKNOWLEDGE         = 0b00010010,
    RC_CMP_SWAP                   = 0b00010011,
    RC_FETCH_ADD                  = 0b00010100,
    RC_SEND_LAST_INVAL            = 0b00010110,
    RC_SEND_ONLY_INVAL            = 0b00010111,

    /* Unreliable Connection (UC)
     * [7:5] = 001 */
    UC_SEND_FIRST                 = 0b00100000,
    UC_SEND_MIDDLE                = 0b00100001,
    UC_SEND_LAST                  = 0b00100010,
    UC_SEND_LAST_IMM              = 0b00100011,
    UC_SEND_ONLY                  = 0b00100100,
    UC_SEND_ONLY_IMM              = 0b00100101,
    UC_RDMA_WRITE_FIRST           = 0b00100110,
    UC_RDMA_WRITE_MIDDLE          = 0b00100111,
    UC_RDMA_WRITE_LAST            = 0b00101000,
    UC_RDMA_WRITE_LAST_IMM        = 0b00101001,
    UC_RDMA_WRITE_ONLY            = 0b00101010,
    UC_RDMA_WRITE_ONLY_IMM        = 0b00101011,

    /* Reliable Datagram (RD)
     * [7:5] = 010 */
    RD_SEND_FIRST                 = 0b01000000,
    RD_SEND_MIDDLE                = 0b01000001,
    RD_SEND_LAST                  = 0b01000010,
    RD_SEND_LAST_IMM              = 0b01000011,
    RD_SEND_ONLY                  = 0b01000100,
    RD_SEND_ONLY_IMM              = 0b01000101,
    RD_RDMA_WRITE_FIRST           = 0b01000110,
    RD_RDMA_WRITE_MIDDLE          = 0b01000111,
    RD_RDMA_WRITE_LAST            = 0b01001000,
    RD_RDMA_WRITE_LAST_IMM        = 0b01001001,
    RD_RDMA_WRITE_ONLY            = 0b01001010,
    RD_RDMA_WRITE_ONLY_IMM        = 0b01001011,
    RD_RDMA_READ_REQUEST          = 0b01001100,
    RD_RDMA_READ_RESPONSE_FIRST   = 0b01001101,
    RD_RDMA_READ_RESPONSE_MIDDLE  = 0b01001110,
    RD_RDMA_READ_RESPONSE_LAST    = 0b01001111,
    RD_RDMA_READ_RESPONSE_ONLY    = 0b01010000,
    RD_ACKNOWLEDGE                = 0b01010001,
    RD_ATOMIC_ACKNOWLEDGE         = 0b01010010,
    RD_CMP_SWAP                   = 0b01010011,
    RD_FETCH_ADD                  = 0b01010100,
    RD_RESYNC                     = 0b01010101,

    /* Unreliable Datagram (UD)
     * [7:5] = 011 */
    UD_SEND_ONLY                  = 0b01100100,
    UD_SEND_ONLY_IMM              = 0b01100101,

    /* CNP
     * [7:5] = 100 */
    CNP                           = 0b10000000,

    /* Extended Reliable Connection (XRC)
     * [7:5] = 101 */
    XRC_SEND_FIRST                = 0b10100000,
    XRC_SEND_MIDDLE               = 0b10100001,
    XRC_SEND_LAST                 = 0b10100010,
    XRC_SEND_LAST_IMM             = 0b10100011,
    XRC_SEND_ONLY                 = 0b10100100,
    XRC_SEND_ONLY_IMM             = 0b10100101,
    XRC_RDMA_WRITE_FIRST          = 0b10100110,
    XRC_RDMA_WRITE_MIDDLE         = 0b10100111,
    XRC_RDMA_WRITE_LAST           = 0b10101000,
    XRC_RDMA_WRITE_LAST_IMM       = 0b10101001,
    XRC_RDMA_WRITE_ONLY           = 0b10101010,
    XRC_RDMA_WRITE_ONLY_IMM       = 0b10101011,
    XRC_RDMA_READ_REQUEST         = 0b10101100,
    XRC_RDMA_READ_RESPONSE_FIRST  = 0b10101101,
    XRC_RDMA_READ_RESPONSE_MIDDLE = 0b10101110,
    XRC_RDMA_READ_RESPONSE_LAST   = 0b10101111,
    XRC_RDMA_READ_RESPONSE_ONLY   = 0b10110000,
    XRC_ACKNOWLEDGE               = 0b10110001,
    XRC_ATOMIC_ACKNOWLEDGE        = 0b10110010,
    XRC_CMP_SWAP                  = 0b10110011,
    XRC_FETCH_ADD                 = 0b10110100,
    XRC_SEND_LAST_INVAL           = 0b10110110,
    XRC_SEND_ONLY_INVAL           = 0b10110111,
};

/** 
 * \class BTH
 * \brief Represents an Infiniband BTH PDU.
 *
 * This class represents an Infiniband BTH (Base Transport Header)
 * PDU. It includes the extended headers, such as AETH, which are
 * enabled if specified by the opcode field in the BTH.
 */
class BTH : public PDU {
public:
    /**
     * \brief This PDU's flag.
     */
    static const PDU::PDUType pdu_flag = PDU::USER_DEFINED_PDU;

    /**
     * \brief Extracts metadata for this protocol based on the buffer provided
     *
     * \param buffer Pointer to a buffer
     * \param total_sz Size of the buffer pointed by buffer
     */
    static metadata extract_metadata(const uint8_t *buffer, uint32_t total_sz);

    /** 
     * \brief BTH constructor.
     *
     * Constructs an instance of BTH. The opcode can be provided,
     * otherwise defaults to RC_SEND_ONLY which has no extended
     * headers.
     * 
     * \param new_opcode The operation code for the new packet.
     */
    explicit BTH(Opcodes new_opcode = RC_SEND_ONLY);

    /**
     * \brief Constructs a BTH object from a buffer.
     * 
     * If there is not enough size for a BTH header, including the
     * required extended headers, then a malformed_packet exception is
     * thrown.
     * 
     * If the opcode expects a payload, then any extra data will be
     * stored in a RawPDU. If a payload is not expected, such as for
     * the RC_ACKNOWLEDGE opcode, a malformed_packet exception is
     * thrown.
     * 
     * \param buffer The buffer from which this PDU will be constructed.
     * \param total_sz The total size of the buffer.
     */
    BTH(const uint8_t* buffer, uint32_t total_sz);
    
    /** 
     * \brief Returns the header size.
     *
     * This method overrides PDU::header_size. This size includes the
     * base and extended headers, if any.
     */
    uint32_t header_size() const;
    
    /** 
     * \brief Returns the trailer size.
     *
     * This method overrides PDU::trailer_size. In the Infiniband
     * transport protocol, a 32-bit ICRC follows the payload or last
     * extended header.
     */
    uint32_t trailer_size() const;
    
    /**
     * \brief Getter for the PDU's type.
     * \sa PDU::pdu_type
     */
    PDUType pdu_type() const { return pdu_flag; }
    
    /**
     * \sa PDU::clone
     */
    BTH* clone() const {
        return new BTH(*this);
    }
    
    /* Getters for BTH fields ***************************************/
    
    /** 
     * \brief Get the Operation Code (OpCode).
     * \return The current opcode.
     */
    Opcodes opcode() const {
        return static_cast<Opcodes>(header_.opcode);
    }
    
    /** 
     * \brief Get the Solicited Event (SE).
     * \return The current se.
     */
    small_uint<1> se() const {
        return header_.se;
    }
    
    /** 
     * \brief Get the Migration Request (M).
     * \return The current m.
     */
    small_uint<1> m() const {
        return header_.m;
    }

    /** 
     * \brief Get the Pad Count (PadCnt).
     * \return The current padcnt.
     */
    small_uint<2> padcnt() const {
        return header_.padcnt;
    }
    
    /** 
     * \brief Get the Transport Header Version (TVer).
     * \return The current tver.
     */
    small_uint<4> tver() const {
        return header_.tver;
    }
    
    /** 
     * \brief Get the Partition Key (P_Key).
     * \return The current p_key.
     */
    uint16_t p_key() const {
        return Endian::be_to_host(header_.p_key);
    }
    
    /** 
     * \brief Get the FECN (F).
     * \return The current f.
     */
    small_uint<1> f() const {
        return header_.f;
    }
    
    /** 
     * \brief Get the BECN (B).
     * \return The current b.
     */
    small_uint<1> b() const {
        return header_.b;
    }
    
    /** 
     * \brief Get the Destination Queue Pair (DestQP).
     * \return The current destqp.
     */
    small_uint<24> destqp() const;
    
    /** 
     * \brief Get the Acknowledge Request (A).
     * \return The current a.
     */
    small_uint<1> a() const {
        return header_.a;
    }
    
    /** 
     * \brief Get the Packet Sequence Number (PSN).
     * \return The current psn.
     */
    small_uint<24> psn() const;

    /**
     * \brief Get the Invariant CRC (ICRC).
     * \return The current icrc.
     */
    uint32_t icrc() const {
        return Endian::be_to_host(icrc_);
    }

    /* Setters for BTH fields ***************************************/
    
    /** 
     * \brief Set the Operation Code (OpCode).
     *
     * \param new_opcode The new opcode.
     */
    void opcode(Opcodes new_opcode);
    
    /** 
     * \brief Set the Solicited Event (SE).
     * \param new_se The new se.
     */
    void se(small_uint<1> new_se) {
        header_.se = new_se;
    }
    
    /** 
     * \brief Set the Migration Request (M).
     * \param new_m The new m.
     */
    void m(small_uint<1> new_m) {
        header_.m = new_m;
    }

    /** 
     * \brief Set the Pad Count (PadCnt).
     * \param new_padcnt The new padcnt.
     */
    void padcnt(small_uint<2> new_padcnt) {
        header_.padcnt = new_padcnt;
    }
    
    /** 
     * \brief Set the Transport Header Version (TVer).
     * \param new_tver The new tver.
     */
    void tver(small_uint<4> new_tver) {
        header_.tver = new_tver;
    }
    
    /** 
     * \brief Set the Partition Key (P_Key).
     * \param new_p_key The new p_key.
     */
    void p_key(uint16_t new_p_key) {
        header_.p_key = Endian::host_to_be(new_p_key);
    }
    
    /** 
     * \brief Set the FECN (F).
     * \param new_f The new f.
     */
    void f(small_uint<1> new_f) {
        header_.f = new_f;
    }
    
    /** 
     * \brief Set the BECN (B).
     * \param new_b The new b.
     */
    void b(small_uint<1> new_b) {
        header_.b = new_b;
    }
    
    /** 
     * \brief Set the Destination Queue Pair (DestQP).
     * \param new_destqp The new destqp.
     */
    void destqp(small_uint<24> new_destqp);
    
    /** 
     * \brief Set the Acknowledge Request (A).
     * \param new_a The new a.
     */
    void a(small_uint<1> new_a) {
        header_.a = new_a;
    }
    
    /** 
     * \brief Set the Packet Sequence Number (PSN).
     * \param new_psn The new psn.
     */
    void psn(small_uint<24> new_psn);

    /**
     * \brief Set the Invariant CRC (ICRC).
     * \param new_icrc The new icrc.
     */
    void icrc(uint32_t new_icrc) {
        icrc_ = Endian::host_to_be(new_icrc);
    }

    /* Getters for RDETH fields *************************************/

    /** 
     * \brief Get the End-to-End Context (EE).
     * \return The current ee.
     */
    small_uint<24> ee() const;
    
    /* Setters for RDETH fields *************************************/

    /** 
     * \brief Set the End-to-End Context (EE).
     * \param new_ee The new ee.
     */
    void ee(small_uint<24> new_ee);

    /* Getters for DETH fields **************************************/

    /** 
     * \brief Get the Q_Key.
     * \return The current q_key.
     */
    uint32_t q_key() const {
        if (!has_deth_) throw field_not_present();
        return Endian::be_to_host(deth_.q_key);
    }
    
    /** 
     * \brief Get the Source Queue Pair (SrcQP).
     * \return The current srcqp.
     */
    small_uint<24> srcqp() const;
    
    /* Setters for DETH fields **************************************/

    /** 
     * \brief Set the Q_Key.
     * \param new_q_key The new q_key.
     */
    void q_key(uint32_t new_q_key) {
        if (!has_deth_) throw field_not_present();
        deth_.q_key = Endian::host_to_be(new_q_key);
    }

    /** 
     * \brief Set the Source Queue Pair (SrcQP).
     * \param new_srcqp The new srcqp.
     */
    void srcqp(small_uint<24> new_srcqp);
    
    /* Getters for RETH fields **************************************/

    /** 
     * \brief Get the Virtual Address (VA).
     * 
     * RETH and ATETH both have a 64-bit VA field. These extended headers
     * are mutually exclusive, so one get function serves both.
     *
     * \return The current va.
     */
    uint64_t va() const {
        if (has_reth_)
            return Endian::be_to_host(reth_.va);
        else if (has_ateth_)
            return Endian::be_to_host(ateth_.va);
        else
            throw field_not_present();
    }
    
    /** 
     * \brief Get the R_Key.
     * 
     * RETH, ATETH, and IETH all have a 32-bit R_Key field. These extended headers
     * are mutually exclusive, so one get function serves all three.
     *
     * \return The current r_key.
     */
    uint32_t r_key() const {
        if (has_reth_)
            return Endian::be_to_host(reth_.r_key);
        else if (has_ateth_)
            return Endian::be_to_host(ateth_.r_key);
        else if (has_ieth_)
            return Endian::be_to_host(ieth_.r_key);
        else
            throw field_not_present();
    }

    /** 
     * \brief Get the DMA Length (DMAlen).
     * \return The current dmalen.
     */
    uint32_t dmalen() const {
        if (!has_reth_) throw field_not_present();
        return Endian::be_to_host(reth_.dmalen);
    }
    
    /* Setters for RETH fields **************************************/

    /** 
     * \brief Set the Virtual Address (AV).
     * 
     * RETH and ATETH both have a 64-bit VA field. These extended headers
     * are mutually exclusive, so one get function serves both.
     *
     * \param new_va The new va.
     */
    void va(uint64_t new_va) {
        if (has_reth_)
            reth_.va = Endian::host_to_be(new_va);
        else if (has_ateth_)
            ateth_.va = Endian::host_to_be(new_va);
        else
            throw field_not_present();
    }
    
    /** 
     * \brief Set the R_Key.
     * 
     * RETH, ATETH, and IETH all have a 32-bit R_Key field. These extended headers
     * are mutually exclusive, so one get function serves all three.
     *
     * \param new_r_key The new r_key.
     */
    void r_key(uint64_t new_r_key) {
        if (has_reth_)
            reth_.r_key = Endian::host_to_be(new_r_key);
        else if (has_ateth_)
            ateth_.r_key = Endian::host_to_be(new_r_key);
        else if (has_ieth_)
            ieth_.r_key = Endian::host_to_be(new_r_key);
        else
            throw field_not_present();
    }

    /** 
     * \brief Set the DMA Length (DMAlen).
     * \param new_dmalen The new dmalen.
     */
    void dmalen(uint32_t new_dmalen) {
        if (!has_reth_) throw field_not_present();
        reth_.dmalen = Endian::host_to_be(new_dmalen);
    }
    
    /* Getters for ATETH fields *************************************/

    /** 
     * \brief Get the Swap (or Add) Data (SwapDt).
     * \return The current swapdt.
     */
    uint32_t swapdt() const {
        if (!has_ateth_) throw field_not_present();
        return Endian::be_to_host(ateth_.swapdt);
    }

    /** 
     * \brief Get the Compare Data (CmpDt).
     * \return The current cmpdt.
     */
    uint32_t cmpdt() const {
        if (!has_ateth_) throw field_not_present();
        return Endian::be_to_host(ateth_.cmpdt);
    }
    
    /* Setters for ATETH fields *************************************/

    /** 
     * \brief Set the Swap (or Add) Data (SwapDt).
     * \param new_swapdt The new swapdt.
     */
    void swapdt(uint32_t new_swapdt) {
        if (!has_ateth_) throw field_not_present();
        ateth_.swapdt = Endian::host_to_be(new_swapdt);
    }

    /** 
     * \brief Set the Compare Data (CmpDt).
     * \param new_cmpdt The new cmpdt.
     */
    void cmpdt(uint32_t new_cmpdt) {
        if (!has_ateth_) throw field_not_present();
        ateth_.cmpdt = Endian::host_to_be(new_cmpdt);
    }

    /* Getters for AETH fields **************************************/
    
    /**
     * \brief Check if packet has the AETH header.
     */
    bool has_aeth() const {
        return has_aeth_;
    }
    
    /** 
     * \brief Get the Syndrome.
     * \return The current syndrome.
     */
    uint8_t syndrome() const {
        if (!has_aeth_) throw field_not_present();
        return aeth_.syndrome;
    }
    
    /** 
     * \brief Get the Message Sequence Number (MSN).
     * \return The current msn.
     */
    small_uint<24> msn() const;
    
    /* Setters for AETH fields **************************************/

    /** 
     * \brief Set the Syndrome.
     * \param new_syndrome The new syndrome.
     */
    void syndrome(uint8_t new_syndrome) {
        if (!has_aeth_) throw field_not_present();
        aeth_.syndrome = new_syndrome;
    }

    /** 
     * \brief Set the Message Sequence Number (MSN).
     * \param new_msn The new msn.
     */
    void msn(small_uint<24> new_msn);
    
    /* Getters for ATAETH fields ************************************/
    
    /** 
     * \brief Get the Original Remote Data (OrigRemDt).
     * \return The current origremdt.
     */
    uint64_t origremdt() const {
        if (!has_ataeth_) throw field_not_present();
        return Endian::be_to_host(ataeth_.origremdt);
    }
    
    /* Setters for ATAETH fields ************************************/
    
    /** 
     * \brief Set the Original Remote Data (OrigRemDt).
     * \param new_origremdt The new origremdt.
     */
    void origremdt(uint64_t new_origremdt) {
        if (!has_ataeth_) throw field_not_present();
        ataeth_.origremdt = Endian::host_to_be(new_origremdt);
    }
    
    /* Getters for IMMDT fields *************************************/
    
    /** 
     * \brief Get the Immediate Data (ImmDt).
     * \return The current immdt.
     */
    uint32_t immdt() const {
        if (!has_immdt_) throw field_not_present();
        return Endian::be_to_host(immdt_.immdt);
    }
    
    /* Setters for IMMDT fields *************************************/
    
    /** 
     * \brief Set the Immediate Data (ImmDt).
     * \param new_immdt The new immdt.
     */
    void immdt(uint32_t new_immdt) {
        if (!has_immdt_) throw field_not_present();
        immdt_.immdt = Endian::host_to_be(new_immdt);
    }
    
    /* Getters for XRCETH fields ************************************/
    
    /** 
     * \brief Get the XRC Shared Receive Queue (XRCSRQ).
     * \return The current xrcsrq.
     */
    small_uint<24> xrcsrq() const;
    
    /* Setters for XRCETH fields ************************************/

    /** 
     * \brief Set the XRC Shared Receive Queue (XRCSRQ).
     * \param new_xrcsrq The new xrcsrq.
     */
    void xrcsrq(small_uint<24> new_xrcsrq);
    
private:
    /* For big endian, the order of bit fields is read left-to-right, 
     * top-to-bottom matching the Infiniband specification.
     * For little endian, the order is flipped within each integral type. */

    /* Base Transport Header */
    TINS_BEGIN_PACK
    struct bth_header {
        /* bytes 0-3 */
        uint8_t  opcode;
    #if TINS_IS_LITTLE_ENDIAN
        uint8_t  tver:4;
        uint8_t  padcnt:2;
        uint8_t  m:1;
        uint8_t  se:1;
    #else
        uint8_t  se:1;
        uint8_t  m:1;
        uint8_t  padcnt:2;
        uint8_t  tver:4;
    #endif
        uint16_t p_key;
        /* bytes 4-7 */
    #if TINS_IS_LITTLE_ENDIAN
        uint32_t reserved_0:6;
        uint32_t b:1;
        uint32_t f:1;
    #else
        uint8_t  f:1;
        uint8_t  b:1;
        uint8_t  reserved_0:6;
    #endif
        uint8_t  destqp[3];
        /* bytes 8-11 */
    #if TINS_IS_LITTLE_ENDIAN
        uint32_t reserved_1:7;
        uint32_t a:1;
    #else
        uint8_t  a:1;
        uint8_t  reserved_1:7;
    #endif
        uint8_t  psn[3];
    } TINS_END_PACK;
    
    /* Reliable Datagram Extended Transport Header (RDETH) */
    TINS_BEGIN_PACK
    struct rdeth_header {
        /* bytes 0-3 */
        uint8_t reserved;
        uint8_t ee[3];
    } TINS_END_PACK;

    /* Datagram Extended Transport Header (DETH) */
    TINS_BEGIN_PACK
    struct deth_header {
        /* bytes 0-3 */
        uint32_t q_key;
        /* bytes 4-7 */
        uint8_t reserved;
        uint8_t srcqp[3];
    } TINS_END_PACK;
    
    /* RDMA Extended Transport Header (RETH) */
    TINS_BEGIN_PACK
    struct reth_header {
        /* bytes 0-7 */
        uint64_t va;
        /* bytes 8-11 */
        uint32_t r_key;
        /* bytes 12-15 */
        uint32_t dmalen;
    } TINS_END_PACK;

    /* Atomic Extended Transport Header (ATETH) */
    TINS_BEGIN_PACK
    struct ateth_header {
        /* bytes 0-7 */
        uint64_t va;
        /* bytes 8-11 */
        uint32_t r_key;
        /* bytes 12-19 */
        uint64_t swapdt;
        /* bytes 20-27 */
        uint64_t cmpdt;
    } TINS_END_PACK;

    /* Acknowledge Extended Transport Header (AETH) */
    TINS_BEGIN_PACK
    struct aeth_header {
        /* bytes 0-3 */
        uint8_t syndrome;
        uint8_t msn[3];
    } TINS_END_PACK;

    /* Atomic Acknowledge Extended Transport Header (ATAETH) */
    TINS_BEGIN_PACK
    struct ataeth_header {
        /* bytes 0-7 */
        uint64_t origremdt;
    } TINS_END_PACK;

    /* Immediate Extended Transport Header (ImmDt) */
    TINS_BEGIN_PACK
    struct immdt_header {
        /* bytes 0-3 */
        uint32_t immdt;
    } TINS_END_PACK;

    /* Invalidate Extended Transport Header (IETH) */
    TINS_BEGIN_PACK
    struct ieth_header {
        /* bytes 0-3 */
        uint32_t r_key;
    } TINS_END_PACK;

    /* XRC Extended Transport Header (XRCETH) */
    TINS_BEGIN_PACK
    struct xrceth_header {
        /* bytes 0-3 */
        uint8_t reserved;
        uint8_t xrcsrq[3];
    } TINS_END_PACK;

    static uint32_t header_size_from_opcode(const Opcodes opcode);
    void update_packet_contents();
    void write_serialization(uint8_t* buffer, uint32_t total_sz);
    
    bth_header header_ = {};
    rdeth_header rdeth_ = {};
    deth_header deth_ = {};
    reth_header reth_ = {};
    ateth_header ateth_ = {};
    aeth_header aeth_ = {};
    ataeth_header ataeth_ = {};
    immdt_header immdt_ = {};
    ieth_header ieth_ = {};
    xrceth_header xrceth_ = {};

    bool has_rdeth_ = false;
    bool has_deth_ = false;
    bool has_reth_ = false;
    bool has_ateth_ = false;
    bool has_aeth_ = false;
    bool has_ataeth_ = false;
    bool has_immdt_ = false;
    bool has_ieth_ = false;
    bool has_xrceth_ = false;
    bool has_payload_ = false;

    uint32_t icrc_ = 0;
};

} // IB
} // Tins

#endif // TINS_IB_BTH_H
