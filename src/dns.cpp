/*
 * libtins is a net packet wrapper library for crafting and
 * interpreting sniffed packets.
 *
 * Copyright (C) 2011 Nasel
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <utility>
#include <stdexcept>
#include <cassert>
#include "dns.h"

using std::string;
using std::list;


Tins::DNS::DNS() : PDU(255), extra_size(0) {
    std::memset(&dns, 0, sizeof(dns));
}

Tins::DNS::DNS(const uint8_t *buffer, uint32_t total_sz) : PDU(255), extra_size(0) {
    if(total_sz < sizeof(dnshdr))
        throw std::runtime_error("Not enough size for a DNS header in the buffer.");
    std::memcpy(&dns, buffer, sizeof(dnshdr));
    const uint8_t *end(buffer + total_sz);
    uint16_t nquestions(questions());
    buffer += sizeof(dnshdr);
    for(uint16_t i(0); i < nquestions; ++i) {
        const uint8_t *ptr(buffer);
        while(ptr < end && *ptr)
            ptr++;
        Query query;
        if((ptr + (sizeof(uint16_t) << 1)) > end)
            throw std::runtime_error("Not enough size for a given query.");
        query.name = string(buffer, ptr);
        ptr++;
        const uint16_t *opt_ptr = reinterpret_cast<const uint16_t*>(ptr);
        query.type = *(opt_ptr++);
        query.qclass = *(opt_ptr++);
        queries.push_back(query);
        total_sz -= reinterpret_cast<const uint8_t*>(opt_ptr) - buffer;
        extra_size += reinterpret_cast<const uint8_t*>(opt_ptr) - buffer;
        buffer = reinterpret_cast<const uint8_t*>(opt_ptr);
    }
    buffer = build_resource_list(ans, buffer, total_sz, answers());
    buffer = build_resource_list(arity, buffer, total_sz, authority());
    build_resource_list(addit, buffer, total_sz, additional());
}

Tins::DNS::DNS(const DNS &other) : PDU(255) {
    copy_fields(&other);
    copy_inner_pdu(other);
}

const uint8_t *Tins::DNS::build_resource_list(list<ResourceRecord*> &lst, const uint8_t *ptr, uint32_t &sz, uint16_t nrecs) {
    const uint8_t *ptr_end(ptr + sz);
    const uint8_t *parse_start(ptr);
    for(uint16_t i(0); i < nrecs; ++i) {
        const uint8_t *this_opt_start(ptr);
        if(ptr + sizeof(uint16_t) > ptr_end)
            throw std::runtime_error("Not enough size for a given resource.");
        ResourceRecord *res;
        if((*ptr  & 0xc0)) {
            uint16_t offset(*reinterpret_cast<const uint16_t*>(ptr));
            offset = Utils::net_to_host_s(offset) & 0x3fff;
            res = new OffsetedResourceRecord(Utils::net_to_host_s(offset));
            ptr += sizeof(uint16_t);
        }
        else {
            const uint8_t *str_end(ptr), *end(ptr + sz);
            while(str_end < end && *str_end)
                str_end++;
            if(str_end == end)
                throw std::runtime_error("Not enough size for a resource domain name.");
            str_end++;
            res = new NamedResourceRecord(string(ptr, str_end));
            ptr = str_end;
        }
        if(ptr + sizeof(res->info) > ptr_end)
            throw std::runtime_error("Not enough size for a resource info.");
        std::memcpy(&res->info, ptr, sizeof(res->info));
        ptr += sizeof(res->info);
        if(ptr + sizeof(uint16_t) > ptr_end)
            throw std::runtime_error("Not enough size for resource data size.");
        res->data_sz = Utils::net_to_host_s(
            *reinterpret_cast<const uint16_t*>(ptr)
        );
        ptr += sizeof(uint16_t);
        if(ptr + res->data_sz > ptr_end)
            throw std::runtime_error("Not enough size for resource data");
        res->data = new uint8_t[res->data_sz];
        if(contains_dname(res->info.type))
            std::memcpy(res->data, ptr, res->data_sz);
        else {
            *(uint32_t*)res->data = Utils::net_to_host_l(*(uint32_t*)ptr);
        }
        
        ptr += res->data_sz;
        extra_size += ptr - this_opt_start;
        lst.push_back(res);
    }
    sz -= ptr - parse_start;
    return ptr;
}

Tins::DNS::~DNS() {
    free_list(ans);
    free_list(arity);
    free_list(addit);
}

void Tins::DNS::free_list(std::list<ResourceRecord*> &lst) {
    while(lst.size()) {
        delete[] lst.front()->data;
        delete lst.front();
        lst.pop_front();
    }
}

uint32_t Tins::DNS::header_size() const {
    return sizeof(dns) + extra_size;
}

void Tins::DNS::id(uint16_t new_id) {
    dns.id = new_id;
}

void Tins::DNS::type(QRType new_qr) {
    dns.qr = new_qr;
}

void Tins::DNS::opcode(uint8_t new_opcode) {
    dns.opcode = new_opcode;
}

void Tins::DNS::authoritative_answer(uint8_t new_aa) {
    dns.aa = new_aa;
}

void Tins::DNS::truncated(uint8_t new_tc) {
    dns.tc = new_tc;
}

void Tins::DNS::recursion_desired(uint8_t new_rd) {
    dns.rd = new_rd;
}

void Tins::DNS::recursion_available(uint8_t new_ra) {
    dns.ra = new_ra;
}

void Tins::DNS::z(uint8_t new_z) {
    dns.z = new_z;
}

void Tins::DNS::authenticated_data(uint8_t new_ad) {
    dns.ad = new_ad;
}

void Tins::DNS::checking_disabled(uint8_t new_cd) {
    dns.cd = new_cd;
}

void Tins::DNS::rcode(uint8_t new_rcode) {
    dns.rcode = new_rcode;
}

bool Tins::DNS::contains_dname(uint16_t type) {
    return type == Utils::net_to_host_s(MX) || type == Utils::net_to_host_s(CNAME) ||
          type == Utils::net_to_host_s(PTR) || type == Utils::net_to_host_s(NS);
}

void Tins::DNS::add_query(const string &name, QueryType type, QueryClass qclass) {
    string new_str;
    parse_domain_name(name, new_str);
    
    queries.push_back(
        Query(new_str, 
        Utils::net_to_host_s(type), 
        Utils::net_to_host_s(qclass))
    );
    extra_size += new_str.size() + 1 + (sizeof(uint16_t) << 1);
    dns.questions = Utils::net_to_host_s(queries.size());
}

void Tins::DNS::add_query(const Query &query) {
    add_query(
        query.name, 
        static_cast<QueryType>(query.type), 
        static_cast<QueryClass>(query.qclass)
    );
}

void Tins::DNS::add_answer(const string &name, QueryType type, QueryClass qclass, uint32_t ttl, uint32_t ip) {
    ResourceRecord *res = make_record(name, type, qclass, ttl, ip);
    ans.push_back(res);
    dns.answers = Utils::net_to_host_s(ans.size());
}

void Tins::DNS::add_answer(const std::string &name, QueryType type, QueryClass qclass,
                        uint32_t ttl, const std::string &dname) {
    string new_str;
    parse_domain_name(dname, new_str);
    ResourceRecord *res = make_record(name, type, qclass, ttl, new_str);
    ans.push_back(res);
    dns.answers = Utils::net_to_host_s(ans.size());
}

void Tins::DNS::add_answer(const std::string &name, QueryType type, QueryClass qclass,
                        uint32_t ttl, const uint8_t *data, uint32_t sz) {
    ResourceRecord *res = make_record(name, type, qclass, ttl, data, sz);
    ans.push_back(res);
    dns.answers = Utils::net_to_host_s(ans.size());
}

void Tins::DNS::add_authority(const string &name, QueryType type, 
  QueryClass qclass, uint32_t ttl, const uint8_t *data, uint32_t sz) {
    ResourceRecord *res = make_record(name, type, qclass, ttl, data, sz);
    arity.push_back(res);
    dns.authority = Utils::net_to_host_s(arity.size());
}

void Tins::DNS::add_additional(const string &name, QueryType type, QueryClass qclass, uint32_t ttl, uint32_t ip) {
    ResourceRecord *res = make_record(name, type, qclass, ttl, ip);
    addit.push_back(res);
    dns.additional = Utils::net_to_host_s(addit.size());
}

Tins::DNS::ResourceRecord *Tins::DNS::make_record(const std::string &name, QueryType type, QueryClass qclass, uint32_t ttl, uint32_t ip) {
    ip = Utils::net_to_host_l(ip);
    return make_record(name, type, qclass, ttl, reinterpret_cast<uint8_t*>(&ip), sizeof(ip));
}

Tins::DNS::ResourceRecord *Tins::DNS::make_record(const std::string &name, QueryType type, QueryClass qclass, uint32_t ttl, const std::string &dname) {
    return make_record(name, type, qclass, ttl, reinterpret_cast<const uint8_t*>(dname.c_str()), dname.size() + 1);
}

Tins::DNS::ResourceRecord *Tins::DNS::make_record(const std::string &name, QueryType type, QueryClass qclass, uint32_t ttl, const uint8_t *ptr, uint32_t len) {
    string nm;
    parse_domain_name(name, nm);
    uint16_t index = find_domain_name(nm);
    ResourceRecord *res;
    if(index)
        res = new OffsetedResourceRecord(Utils::net_to_host_s(index), ptr, len);
    else
        res = new NamedResourceRecord(nm, ptr, len);
    res->info.type = Utils::net_to_host_s(type);
    res->info.qclass = Utils::net_to_host_s(qclass);
    res->info.ttl = Utils::net_to_host_l(ttl);
    extra_size += res->size();
    return res;
}

uint32_t Tins::DNS::find_domain_name(const std::string &dname) {
    uint16_t index(sizeof(dnshdr));
    list<Query>::const_iterator it(queries.begin());
    for(; it != queries.end() && it->name != dname; ++it)
        index += it->name.size() + 1 + (sizeof(uint16_t) << 1);
    if(it != queries.end() ||
       find_domain_name(dname, ans, index) || 
       find_domain_name(dname, arity, index) || 
       find_domain_name(dname, addit, index))
        return index;
    else
        return 0;
}

bool Tins::DNS::find_domain_name(const std::string &dname, const std::list<ResourceRecord*> &lst, uint16_t &out) {
    list<ResourceRecord*>::const_iterator it(lst.begin());
    while(it != lst.end()) {
        if((*it)->matches(dname))
            break;
        out += (*it)->size();
        ++it;
    }
    return it != lst.end();
}

void Tins::DNS::parse_domain_name(const std::string &dn, std::string &out) const {
    size_t last_index(0), index;
    while((index = dn.find('.', last_index+1)) != string::npos) {
        out.push_back(index - last_index);
        out.append(dn.begin() + last_index, dn.begin() + index);
        last_index = index + 1; //skip dot
    }
    out.push_back(dn.size() - last_index);
    out.append(dn.begin() + last_index, dn.end());
}

void Tins::DNS::unparse_domain_name(const std::string &dn, std::string &out) const {
    if(dn.size()) {
        uint32_t index(1), len(dn[0]);
        while(index + len < dn.size() && len) {
            if(index != 1)
                out.push_back('.');
            out.append(dn.begin() + index, dn.begin() + index + len);
            index += len;
            if(index < dn.size() - 1)
                len = dn[index];
            index++;
        }
        if(index < dn.size()) {
            out.push_back('.');
            out.append(dn.begin() + index, dn.end());
        }
    }
}

void Tins::DNS::write_serialization(uint8_t *buffer, uint32_t total_sz, const PDU *parent) {
    assert(total_sz >= sizeof(dns) + extra_size);
    std::memcpy(buffer, &dns, sizeof(dns)); 
    buffer += sizeof(dns);
    for(list<Query>::const_iterator it(queries.begin()); it != queries.end(); ++it) {
        std::memcpy(buffer, it->name.c_str(), it->name.size() + 1);
        buffer += it->name.size() + 1;
        *((uint16_t*)buffer) = it->type;
        buffer += sizeof(uint16_t);
        *((uint16_t*)buffer) = it->qclass;
        buffer += sizeof(uint16_t);
    }
    buffer = serialize_list(ans, buffer);
    buffer = serialize_list(arity, buffer);
    buffer = serialize_list(addit, buffer);
}

uint8_t *Tins::DNS::serialize_list(const std::list<ResourceRecord*> &lst, uint8_t *buffer) const {
    for(list<ResourceRecord*>::const_iterator it(lst.begin()); it != lst.end(); ++it)
        buffer += (*it)->write(buffer);
    return buffer;
}

void Tins::DNS::add_suffix(uint32_t index, const uint8_t *data, uint32_t sz) {
    uint32_t i(0), suff_sz(data[0]);
    SuffixMap::iterator it;
    while((i + suff_sz + 1 <= sz || (suff_sz == 0xc0 && i + 1 < sz)) && suff_sz) {
        if((suff_sz & 0xc0)) {
            if((it = suffixes.find(data[i+1])) != suffixes.end())
                suffix_indices[index + i] = data[i+1];
            i += sizeof(uint16_t);
        }
        else {
            ++i;
            suffixes.insert(std::make_pair(index + i - 1, string(data + i, data + i + suff_sz)));
            i += suff_sz;
        }        
        if(i < sz)
            suff_sz = data[i];
    }
}

uint32_t Tins::DNS::build_suffix_map(uint32_t index, const list<ResourceRecord*> &lst) {
    const string *str;
    for(list<ResourceRecord*>::const_iterator it(lst.begin()); it != lst.end(); ++it) {
        str = (*it)->dname_pointer();
        if(str) {
            add_suffix(index, (uint8_t*)str->c_str(), str->size());
            index += str->size() + 1;
        }
        else
            index += sizeof(uint16_t);
        index += sizeof(ResourceRecord::Info) + sizeof(uint16_t);
        uint32_t sz((*it)->data_size());
        const uint8_t *ptr = (*it)->data_pointer();
        if((*it)->info.type == Utils::net_to_host_s(MX)) {
            ptr += 2;
            sz -= 2;
            index += 2;
        }
        if(contains_dname((*it)->info.type))
            add_suffix(index, ptr, sz);
        index += sz;
    }
    return index;
}

uint32_t Tins::DNS::build_suffix_map(uint32_t index, const list<Query> &lst) {
    for(list<Query>::const_iterator it(lst.begin()); it != lst.end(); ++it) {
        add_suffix(index, (uint8_t*)it->name.c_str(), it->name.size());
        index += it->name.size() + 1 + (sizeof(uint16_t) << 1);
    }
    return index;
}

void Tins::DNS::build_suffix_map() {
    uint32_t index(sizeof(dnshdr));
    index = build_suffix_map(index, queries);
    index = build_suffix_map(index, ans);
    index = build_suffix_map(index, arity);
    build_suffix_map(index, addit);
}

void Tins::DNS::compose_name(const uint8_t *ptr, uint32_t sz, std::string &out) {
    uint32_t i(0);
    while(i < sz) {
        if(i)
            out.push_back('.');
        if((ptr[i] & 0xc0)) {
            uint16_t index = Utils::net_to_host_s(*((uint16_t*)(ptr + i)));
            index &= 0x3fff;
            SuffixMap::iterator it(suffixes.find(index));
            SuffixIndices::iterator suff_it(suffix_indices.find(index));
            assert(it != suffixes.end() && suff_it == suffix_indices.end());
            bool first(true);
            do {
                if(it != suffixes.end()) {
                    if(!first)
                        out.push_back('.');
                    first = false;
                    out += it->second;
                    index += it->second.size() + 1;
                }
                else
                    index = suff_it->second;
                it = suffixes.find(index);
                if(it == suffixes.end())
                    suff_it = suffix_indices.find(index);
                
            } while(it != suffixes.end() || suff_it != suffix_indices.end());
            break;
        }
        else {
            uint8_t suff_sz(ptr[i]);
            i++;
            if(i + suff_sz < sz)
                out.append(ptr + i, ptr + i + suff_sz);
            i += suff_sz;
        }
    }
}

void Tins::DNS::convert_resources(const std::list<ResourceRecord*> &lst, std::list<Resource> &res) {
    if(!suffixes.size())
        build_suffix_map();
    const string *str_ptr;
    const uint8_t *ptr;
    uint32_t sz;
    for(list<ResourceRecord*>::const_iterator it(lst.begin()); it != lst.end(); ++it) {
        string dname, addr;
        if((str_ptr = (*it)->dname_pointer())) 
            compose_name(reinterpret_cast<const uint8_t*>(str_ptr->c_str()), str_ptr->size(), dname);
        else {
            uint16_t offset = static_cast<OffsetedResourceRecord*>(*it)->offset;
            compose_name((uint8_t*)&offset, 2, dname);
        }
        ptr = (*it)->data_pointer();
        sz = (*it)->data_size();
        if(sz == 4)
            addr = Utils::ip_to_string(*(uint32_t*)ptr);
        else {
            if((*it)->info.type ==  Utils::net_to_host_s(MX)) {
                ptr += 2;
                sz -= 2;
            }
            compose_name(ptr, sz, addr);
        }
        res.push_back(
            Resource(dname, addr, Utils::net_to_host_s((*it)->info.type), 
            Utils::net_to_host_s((*it)->info.qclass), Utils::net_to_host_l((*it)->info.ttl))
        );
    }
}

list<Tins::DNS::Query> Tins::DNS::dns_queries() const { 
    list<Query> output;
    for(std::list<Query>::const_iterator it(queries.begin()); it != queries.end(); ++it) {
        string dn;
        unparse_domain_name(it->name, dn);
        output.push_back(Query(dn, Utils::net_to_host_s(it->type), Utils::net_to_host_s(it->qclass)));
    }
    return output;
}

list<Tins::DNS::Resource> Tins::DNS::dns_answers() {
    list<Resource> res;
    convert_resources(ans, res);
    return res;
}

Tins::PDU *Tins::DNS::clone_pdu() const {
    DNS *new_pdu = new DNS();
    new_pdu->copy_fields(this);
    new_pdu->copy_inner_pdu(*this);
    return new_pdu;
}

void Tins::DNS::copy_fields(const DNS *other) {
    std::memcpy(&dns, &other->dns, sizeof(dns));
    extra_size = other->extra_size;
    queries = other->queries;
    copy_list(other->ans, ans);
    copy_list(other->arity, arity);
    copy_list(other->addit, addit);
}

void Tins::DNS::copy_list(const list<ResourceRecord*> &from, list<ResourceRecord*> &to) const {
    for(list<ResourceRecord*>::const_iterator it(from.begin()); it != from.end(); ++it) {
        to.push_back((*it)->clone());
    }
}

// ResourceRecord

void Tins::DNS::ResourceRecord::copy_fields(ResourceRecord *other) const {
    std::memcpy(&other->info, &info, sizeof(info));
    other->data_sz = data_sz;
    other->data = new uint8_t[data_sz];
    std::memcpy(other->data, data, data_sz);
}

uint32_t Tins::DNS::ResourceRecord::write(uint8_t *buffer) const {
    uint32_t sz(do_write(buffer));
    buffer += sz;
    std::memcpy(buffer, &info, sizeof(info));
    buffer += sizeof(info);
    *((uint16_t*)buffer) = Utils::net_to_host_s(data_sz);
    buffer += sizeof(uint16_t);
    std::memcpy(buffer, data, data_sz);
    return sz + sizeof(info) + sizeof(uint16_t) + data_sz;
}

Tins::DNS::ResourceRecord *Tins::DNS::OffsetedResourceRecord::clone() const {
    ResourceRecord *r = new OffsetedResourceRecord(offset);
    copy_fields(r);
    return r;
}

Tins::DNS::ResourceRecord *Tins::DNS::NamedResourceRecord::clone() const {
    ResourceRecord *r = new NamedResourceRecord(name);
    copy_fields(r);
    return r;
}