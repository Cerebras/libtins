/*
 * Copyright (c) 2017, Matias Fontanini
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * 
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following disclaimer
 *   in the documentation and/or other materials provided with the
 *   distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <cstring>
#include <tins/tcp.h>
#include <tins/ip.h>
#include <tins/ipv6.h>
#include <tins/constants.h>
#include <tins/rawpdu.h>
#include <tins/exceptions.h>
#include <tins/pdu_allocator.h>
#include <tins/memory_helpers.h>
#include <tins/utils/checksum_utils.h>

using std::vector;
using std::pair;

using Tins::Memory::PduInputMemoryStream;
using Tins::Memory::OutputMemoryStream;

namespace Tins {

const uint16_t TCP::DEFAULT_WINDOW = 32678;

PDU::metadata TCP::extract_metadata(const uint8_t *buffer, uint32_t total_sz) {
    if (TINS_UNLIKELY(total_sz < sizeof(tcp_header))) {
        throw malformed_packet();
    }
    const tcp_header* header = (const tcp_header*)buffer;
    return metadata(header->doff * 4, pdu_flag, PDU::UNKNOWN);
}

TCP::TCP(uint16_t dport, uint16_t sport) 
: header_() {
    this->dport(dport);
    this->sport(sport);
    data_offset(sizeof(tcp_header) / sizeof(uint32_t));
    window(DEFAULT_WINDOW);
}

TCP::TCP(const uint8_t* buffer, uint32_t total_sz) {
    PduInputMemoryStream stream(this, buffer, total_sz);
    stream.read(header_);

    // Check that we have at least the amount of bytes we need and not less
    if (TINS_UNLIKELY(data_offset() * sizeof(uint32_t) > total_sz || 
                      data_offset() * sizeof(uint32_t) < sizeof(tcp_header))) {
        malformed(true);
        return;
    }
    const uint8_t* header_end = buffer + (data_offset() * sizeof(uint32_t));

    if (stream.pointer() < header_end) {
        // Estimate about 4 bytes per option and reserver that so we avoid doing 
        // multiple reallocations on the vector
        options_.reserve((header_end - stream.pointer()) / sizeof(uint32_t));
    }

    while (stream.pointer() < header_end) {
        const OptionTypes option_type = (OptionTypes)stream.read<uint8_t>();
        if (option_type == EOL) {
            stream.skip(header_end - stream.pointer());
            break;
        }
        else if (option_type == NOP) {
            #if TINS_IS_CXX11
            add_option(option_type, 0);
            #else
            add_option(option(option_type, 0));
            #endif // TINS_IS_CXX11
        }
        else {
            // Extract the length
            uint32_t len = stream.read<uint8_t>();
            const uint8_t* data_start = stream.pointer();

            // We need to subtract the option type and length from the size
            if (TINS_UNLIKELY(len < sizeof(uint8_t) << 1)) {
                malformed(true);
                return;
            }
            len -= (sizeof(uint8_t) << 1);
            // Make sure we have enough bytes for the advertised option payload length
            if (TINS_UNLIKELY(data_start + len > header_end)) {
                malformed(true);
                return;
            }
            // If we're using C++11, use the variadic template overload
            #if TINS_IS_CXX11
            add_option(option_type, data_start, data_start + len);
            #else
            add_option(option(option_type, data_start, data_start + len));
            #endif // TINS_IS_CXX11
            // Skip the option's payload
            stream.skip(len);
        }
    }
    
    // If we still have any bytes left
    if (stream) {
        PDU* new_pdu = nullptr;
        if ((new_pdu = Internals::allocate<TCP>(
                 {Allocators::SRC_PORT, sport()}, stream.pointer(), stream.size()))) {
        }
        else if ((new_pdu = Internals::allocate<TCP>(
                      {Allocators::DST_PORT, dport()}, stream.pointer(), stream.size()))) {
        }
        else {
            new_pdu = new RawPDU(stream.pointer(), stream.size());
        }
        
        inner_pdu(new_pdu);
    }
}

void TCP::dport(uint16_t new_dport) {
    header_.dport = Endian::host_to_be(new_dport);
}

void TCP::sport(uint16_t new_sport) {
    header_.sport = Endian::host_to_be(new_sport);
}

void TCP::seq(uint32_t new_seq) {
    header_.seq = Endian::host_to_be(new_seq);
}

void TCP::ack_seq(uint32_t new_ack_seq) {
    header_.ack_seq = Endian::host_to_be(new_ack_seq);
}

void TCP::window(uint16_t new_window) {
    header_.window = Endian::host_to_be(new_window);
}

void TCP::checksum(uint16_t new_check) {
    header_.check = Endian::host_to_be(new_check);
}

uint16_t TCP::calculate_checksum() const {
    const uint32_t options_size = calculate_options_size();
    const uint32_t padded_options_size = pad_options_size(options_size);
    
    // Create buffer to hold header and write it to a stream
    std::vector<uint8_t> buffer_vec(sizeof(header_) + padded_options_size);
    OutputMemoryStream stream(buffer_vec.data(), buffer_vec.size());
    stream.write(header_);
    stream_options(stream, (padded_options_size - options_size));

    if (inner_pdu()) {
        auto payload = inner_pdu()->clone()->serialize();
        buffer_vec.insert(buffer_vec.end(), payload.begin(), payload.end());
    }

    return calculate_checksum(buffer_vec.data(), buffer_vec.size(), header_.check);
}

void TCP::urg_ptr(uint16_t new_urg_ptr) {
    header_.urg_ptr = Endian::host_to_be(new_urg_ptr);
}

void TCP::data_offset(small_uint<4> new_doff) {
    this->header_.doff = new_doff;
}

void TCP::mss(uint16_t value) {
    value = Endian::host_to_be(value);
    add_option(option(MSS, 2, (uint8_t*)&value));
}

uint16_t TCP::mss() const {
    return generic_search<uint16_t>(MSS);
}

void TCP::winscale(uint8_t value) {
    add_option(option(WSCALE, 1, &value));
}

uint8_t TCP::winscale() const {
    return generic_search<uint8_t>(WSCALE);
}

void TCP::sack_permitted() {
    add_option(option(SACK_OK, 0));
}

bool TCP::has_sack_permitted() const {
    return search_option(SACK_OK) != NULL;
}

void TCP::sack(const sack_type& edges) {
    vector<uint8_t> value(edges.size() * sizeof(uint32_t));
    if (edges.size()) {
        OutputMemoryStream stream(value);
        for (sack_type::const_iterator it = edges.begin(); it != edges.end(); ++it) {
            stream.write_be(*it);
        }
    }
    add_option(option(SACK, (uint8_t)value.size(), &value[0]));
}

TCP::sack_type TCP::sack() const {
    const option* opt = search_option(SACK);
    if (!opt) {
        throw option_not_found();
    }
    return opt->to<sack_type>();
}

void TCP::timestamp(uint32_t value, uint32_t reply) {
    uint64_t buffer = (uint64_t(value) << 32) | reply;
    buffer = Endian::host_to_be(buffer);
    add_option(option(TSOPT, 8, (uint8_t*)&buffer));
}

pair<uint32_t, uint32_t> TCP::timestamp() const {
    const option* opt = search_option(TSOPT);
    if (!opt) {
        throw option_not_found();
    }
    return opt->to<pair<uint32_t, uint32_t> >();
}

void TCP::altchecksum(AltChecksums value) {
    uint8_t int_value = value;
    add_option(option(ALTCHK, 1, &int_value));
}

TCP::AltChecksums TCP::altchecksum() const {
    return static_cast<AltChecksums>(generic_search<uint8_t>(ALTCHK));
}

small_uint<1> TCP::get_flag(Flags tcp_flag) const {
    switch (tcp_flag) {
        case FIN:
            return header_.flags.fin;
            break;
        case SYN:
            return header_.flags.syn;
            break;
        case RST:
            return header_.flags.rst;
            break;
        case PSH:
            return header_.flags.psh;
            break;
        case ACK:
            return header_.flags.ack;
            break;
        case URG:
            return header_.flags.urg;
            break;
        case ECE:
            return header_.flags.ece;
            break;
        case CWR:
            return header_.flags.cwr;
            break;
        default:
            return 0;
            break;
    };
}

small_uint<12> TCP::flags() const {
    return (header_.res1 << 8) | header_.flags_8;
}

void TCP::set_flag(Flags tcp_flag, small_uint<1> value) {
    switch (tcp_flag) {
        case FIN:
            header_.flags.fin = value;
            break;
        case SYN:
            header_.flags.syn = value;
            break;
        case RST:
            header_.flags.rst = value;
            break;
        case PSH:
            header_.flags.psh = value;
            break;
        case ACK:
            header_.flags.ack = value;
            break;
        case URG:
            header_.flags.urg = value;
            break;
        case ECE:
            header_.flags.ece = value;
            break;
        case CWR:
            header_.flags.cwr = value;
            break;
    };
}

void TCP::flags(small_uint<12> value) {
    header_.res1 = (value >> 8) & 0x0f;
    header_.flags_8 = value & 0xff;
}

void TCP::add_option(const option& opt) {
    options_.push_back(opt);
}

uint32_t TCP::header_size() const {
    return sizeof(header_) + pad_options_size(calculate_options_size());
}

uint16_t TCP::calculate_checksum(const uint8_t* buffer,
                                 const uint32_t total_sz,
                                 const uint16_t old_checksum) const {
    uint32_t check = 0;
    const PDU* parent = parent_pdu();
    if (const Tins::IP* ip_packet = tins_cast<const Tins::IP*>(parent)) {
        check = Utils::pseudoheader_checksum(
            ip_packet->src_addr(),  
            ip_packet->dst_addr(), 
            size(), 
            Constants::IP::PROTO_TCP
        ) + Utils::sum_range(buffer, buffer + total_sz);
    }
    else if (const Tins::IPv6* ipv6_packet = tins_cast<const Tins::IPv6*>(parent)) {
        check = Utils::pseudoheader_checksum(
            ipv6_packet->src_addr(),  
            ipv6_packet->dst_addr(), 
            size(), 
            Constants::IP::PROTO_TCP
        ) + Utils::sum_range(buffer, buffer + total_sz);
    }
    else {
        // No pseudo-header available, so treat its checksum as 0.
        check = Utils::sum_range(buffer, buffer + total_sz);
    }

    check -= old_checksum;
    return Endian::host_to_be<uint16_t>(~Utils::fold_sum(check));
}

void TCP::write_serialization(uint8_t* buffer, uint32_t total_sz) {
    OutputMemoryStream stream(buffer, total_sz);

    if (inner_pdu()) {
        if (Internals::pdu_type_registered<TCP>(inner_pdu()->pdu_type())) {
            auto pdu_id = Internals::pdu_type_to_id<TCP>(inner_pdu()->pdu_type());
            if (pdu_id.dir == Allocators::SRC_PORT) {
                sport(pdu_id.port);
            } else {
                dport(pdu_id.port);
            }
        }
    }
    
    const uint32_t options_size = calculate_options_size();
    const uint32_t padded_options_size = pad_options_size(options_size);

    header_.doff = (sizeof(tcp_header) + padded_options_size) / sizeof(uint32_t);
    stream.write(header_);
    stream_options(stream, (padded_options_size - options_size));

    checksum(calculate_checksum(buffer, total_sz, header_.check));
    ((tcp_header*)buffer)->check = header_.check;
}

const TCP::option* TCP::search_option(OptionTypes type) const {
    // Search for the iterator. If we found something, return it, otherwise return nullptr.
    options_type::const_iterator iter = search_option_iterator(type);
    return (iter != options_.end()) ? &*iter : 0;
}

TCP::options_type::const_iterator TCP::search_option_iterator(OptionTypes type) const {
    return Internals::find_option_const<option>(options_, type);
}

TCP::options_type::iterator TCP::search_option_iterator(OptionTypes type) {
    return Internals::find_option<option>(options_, type);
}

/* options */

void TCP::write_option(const option& opt, OutputMemoryStream& stream) const {
    stream.write<uint8_t>(opt.option());
    // Only do this for non EOL nor NOP options 
    if (opt.option() > 1) {
        uint8_t length = opt.length_field();
        // Only add the identifier and size field sizes if the length
        // field hasn't been spoofed.
        if (opt.length_field() == opt.data_size()) {
            length += (sizeof(uint8_t) << 1);
        }
        stream.write(length);
        stream.write(opt.data_ptr(), opt.data_size());
    }
}

void TCP::stream_options(OutputMemoryStream &stream, const uint32_t pad_size) const {
    // Write options to stream
    for (options_type::const_iterator it = options_.begin(); it != options_.end(); ++it) {
        write_option(*it, stream);
    }

    // Add option padding
    stream.fill(pad_size, 0);
}

uint32_t TCP::calculate_options_size() const {
    uint32_t options_size = 0;
    for (options_type::const_iterator iter = options_.begin(); iter != options_.end(); ++iter) {
        const option& opt = *iter;
        options_size += sizeof(uint8_t);
        // SACK_OK contains length but not data
        if (opt.data_size() || opt.option() == SACK_OK) {
            options_size += sizeof(uint8_t);    
            options_size += static_cast<uint16_t>(opt.data_size());
        }
    }
    return options_size;    
}

uint32_t TCP::pad_options_size(uint32_t size) const {
    uint8_t padding = size & 3;
    return padding ? (size - padding + 4) : size;
}

bool TCP::remove_option(OptionTypes type) {
    options_type::iterator iter = search_option_iterator(type);
    if (iter == options_.end()) {
        return false;
    }
    options_.erase(iter);
    return true;
}

bool TCP::matches_response(const uint8_t* ptr, uint32_t total_sz) const {
    if (total_sz < sizeof(header_)) {
        return false;
    }
    const tcp_header* tcp_ptr = (const tcp_header*)ptr;
    if (tcp_ptr->sport == header_.dport && tcp_ptr->dport == header_.sport) {
        const uint32_t data_offset = tcp_ptr->doff * sizeof(uint32_t);
        uint32_t sz = (total_sz < data_offset) ? total_sz : data_offset;
        return inner_pdu() ? inner_pdu()->matches_response(ptr + sz, total_sz - sz) : true;
    }
    else
        return false;
}

} // Tins
