#include <gtest/gtest.h>
#include <arpa/inet.h>
#include <tins/ib_bth.h>
#include <tins/ethernetII.h>
#include <tins/udp.h>
#include <tins/ip.h>
#include <tins/rawpdu.h>
#include <tins/pdu_allocator.h>

#include <string>

using namespace std;
using namespace Tins;

class RoCEv2Test : public testing::Test {
public:
    void SetUp(void) override;
    void test_equals(const IB::BTH& pdu1, const IB::BTH& pdu2);
    
    static const string payload_0;
    static const uint8_t expected_packet_0[];
    static const uint8_t expected_packet_1[];
    static const uint8_t expected_packet_2[];
    static const uint8_t expected_packet_3[];
    static const uint8_t expected_packet_4[];
    static const uint8_t expected_packet_5[];
};

void RoCEv2Test::SetUp(void) {
    // If UDP dport is 4791, then next header is IB::BTH.
    Allocators::register_allocator<UDP, IB::BTH>({Allocators::DST_PORT, 4791});
}

void RoCEv2Test::test_equals(const IB::BTH& bth1, const IB::BTH& bth2) {
    EXPECT_EQ(bth1.header_size(), bth2.header_size());
    EXPECT_EQ(bth1.trailer_size(), bth2.trailer_size());
    EXPECT_EQ(bth1.inner_pdu() != NULL, bth2.inner_pdu() != NULL);
    
    EXPECT_EQ(bth1.opcode(), bth2.opcode());
    EXPECT_EQ(bth1.se(),     bth2.se());
    EXPECT_EQ(bth1.m(),      bth2.m());
    EXPECT_EQ(bth1.padcnt(), bth2.padcnt());
    EXPECT_EQ(bth1.tver(),   bth2.tver());
    EXPECT_EQ(bth1.p_key(),  bth2.p_key());
    EXPECT_EQ(bth1.f(),      bth2.f());
    EXPECT_EQ(bth1.b(),      bth2.b());
    EXPECT_EQ(bth1.destqp(), bth2.destqp());
    EXPECT_EQ(bth1.a(),      bth2.a());
    EXPECT_EQ(bth1.psn(),    bth2.psn());
    EXPECT_EQ(bth1.icrc(),   bth2.icrc());

    EXPECT_EQ(bth1.has_aeth(), bth2.has_aeth());
    if (bth1.has_aeth()) {
        EXPECT_EQ(bth1.syndrome(), bth2.syndrome());
        EXPECT_EQ(bth1.msn(),      bth2.msn());
    }

    //XXX Add all the other extended headers in the pattern of AETH.
}

TEST_F(RoCEv2Test, DefaultConstructor) {
    IB::BTH bth1;

    EXPECT_EQ(IB::RC_SEND_ONLY, bth1.opcode());
    EXPECT_EQ(0U, bth1.se());
    EXPECT_EQ(0U, bth1.m());
    EXPECT_EQ(0U, bth1.padcnt());
    EXPECT_EQ(0U, bth1.tver());
    EXPECT_EQ(0U, bth1.p_key());
    EXPECT_EQ(0U, bth1.f());
    EXPECT_EQ(0U, bth1.b());
    EXPECT_EQ(0U, bth1.destqp());
    EXPECT_EQ(0U, bth1.a());
    EXPECT_EQ(0U, bth1.psn());
    EXPECT_EQ(0U, bth1.icrc());
    EXPECT_EQ(false, bth1.has_aeth());
}

TEST_F(RoCEv2Test, AcknowledgeConstructor) {
    IB::BTH bth1(IB::RC_ACKNOWLEDGE);

    EXPECT_EQ(IB::RC_ACKNOWLEDGE, bth1.opcode());
    EXPECT_EQ(0U, bth1.se());
    EXPECT_EQ(0U, bth1.m());
    EXPECT_EQ(0U, bth1.padcnt());
    EXPECT_EQ(0U, bth1.tver());
    EXPECT_EQ(0U, bth1.p_key());
    EXPECT_EQ(0U, bth1.f());
    EXPECT_EQ(0U, bth1.b());
    EXPECT_EQ(0U, bth1.destqp());
    EXPECT_EQ(0U, bth1.a());
    EXPECT_EQ(0U, bth1.psn());
    EXPECT_EQ(0U, bth1.icrc());
    EXPECT_EQ(true, bth1.has_aeth());
    EXPECT_EQ(0U, bth1.syndrome());
    EXPECT_EQ(0U, bth1.msn());
}

TEST_F(RoCEv2Test, BaseHeaderFields) {
    IB::BTH bth1;
    std::vector<uint8_t> pkt2(16, 0);
    pkt2[0] = IB::RC_SEND_ONLY;
    
    bth1.se(1);
    pkt2[1] = 1 << 7;
    {
        IB::BTH bth2{pkt2.data(), static_cast<uint32_t>(pkt2.size())};
        test_equals(bth1, bth2);
    }

    bth1.se(0);
    bth1.m(1);
    pkt2[1] = 1 << 6;
    {
        IB::BTH bth2{pkt2.data(), static_cast<uint32_t>(pkt2.size())};
        test_equals(bth1, bth2);
    }

    bth1.m(0);
    bth1.padcnt(3);
    pkt2[1] = 3 << 4;
    {
        IB::BTH bth2{pkt2.data(), static_cast<uint32_t>(pkt2.size())};
        test_equals(bth1, bth2);
    }

    bth1.padcnt(0);
    bth1.tver(0xf);
    pkt2[1] = 0xf;
    {
        IB::BTH bth2{pkt2.data(), static_cast<uint32_t>(pkt2.size())};
        test_equals(bth1, bth2);
    }

    bth1.tver(0);
    bth1.p_key(0x5678);
    pkt2[1] = 0;
    pkt2[2] = 0x56;
    pkt2[3] = 0x78;
    {
        IB::BTH bth2{pkt2.data(), static_cast<uint32_t>(pkt2.size())};
        test_equals(bth1, bth2);
    }

    bth1.p_key(0);
    bth1.f(1);
    pkt2[2] = 0;
    pkt2[3] = 0;
    pkt2[4] = 1 << 7;
    {
        IB::BTH bth2{pkt2.data(), static_cast<uint32_t>(pkt2.size())};
        test_equals(bth1, bth2);
    }

    bth1.f(0);
    bth1.b(1);
    pkt2[4] = 1 << 6;
    {
        IB::BTH bth2{pkt2.data(), static_cast<uint32_t>(pkt2.size())};
        test_equals(bth1, bth2);
    }

    bth1.b(0);
    bth1.destqp(0x123456);
    pkt2[4] = 0;
    pkt2[5] = 0x12;
    pkt2[6] = 0x34;
    pkt2[7] = 0x56;
    {
        IB::BTH bth2{pkt2.data(), static_cast<uint32_t>(pkt2.size())};
        test_equals(bth1, bth2);
    }

    bth1.destqp(0);
    bth1.a(1);
    pkt2[5] = 0;
    pkt2[6] = 0;
    pkt2[7] = 0;
    pkt2[8] = 1 << 7;
    {
        IB::BTH bth2{pkt2.data(), static_cast<uint32_t>(pkt2.size())};
        test_equals(bth1, bth2);
    }
    
    bth1.a(0);
    bth1.psn(0x9abcde);
    pkt2[8] = 0;
    pkt2[9] = 0x9a;
    pkt2[10] = 0xbc;
    pkt2[11] = 0xde;
    {
        IB::BTH bth2{pkt2.data(), static_cast<uint32_t>(pkt2.size())};
        test_equals(bth1, bth2);
    }

    bth1.psn(0);
    bth1.icrc(0x56789abc);
    pkt2[9] = 0;
    pkt2[10] = 0;
    pkt2[11] = 0;
    pkt2[12] = 0x56;
    pkt2[13] = 0x78;
    pkt2[14] = 0x9a;
    pkt2[15] = 0xbc;
    {
        IB::BTH bth2{pkt2.data(), static_cast<uint32_t>(pkt2.size())};
        test_equals(bth1, bth2);
    }
}

TEST_F(RoCEv2Test, AethFields) {
    IB::BTH bth1(IB::RC_ACKNOWLEDGE);
    std::vector<uint8_t> pkt2(20, 0);
    pkt2[0] = IB::RC_ACKNOWLEDGE;
    
    bth1.syndrome(0x39);
    pkt2[12] = 0x39;
    {
        IB::BTH bth2{pkt2.data(), static_cast<uint32_t>(pkt2.size())};
        test_equals(bth1, bth2);
    }

    bth1.syndrome(0);
    bth1.msn(0x27f59d);
    pkt2[12] = 0;
    pkt2[13] = 0x27;
    pkt2[14] = 0xf5;
    pkt2[15] = 0x9d;
    {
        IB::BTH bth2{pkt2.data(), static_cast<uint32_t>(pkt2.size())};
        test_equals(bth1, bth2);
    }
}

const string RoCEv2Test::payload_0 = (
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do \n"
    "eiusmod tempor incididunt ut labore et dolore magna aliqua. Nibh \n"
    "ipsum consequat nisl vel pretium lectus. Fermentum posuere urna nec \n"
    "tincidunt praesent semper feugiat nibh sed. Lorem ipsum dolor sit amet \n"
    "consectetur adipiscing. Velit egestas dui id ornare arcu odio. Dui \n"
    "faucibus in ornare quam viverra orci. Et netus et malesuada fames. \n"
    "Eget duis at tellus at urna. Vulputate dignissim suspendisse in est. \n"
    "Tincidunt eget nullam non nisi est sit amet facilisis magna. Fermentum \n"
    "dui faucibus in ornare quam viverra. Semper viverra nam libero justo \n"
    "laoreet sit.\n\n"
    "Vitae proin sagittis nisl rhoncus mattis rhoncus urna neque. Rutrum \n"
    "tellus pellentesque eu tincidunt tortor aliquam. Gravida arcu ac \n"
    "tortor dignissim convallis. Urna condimentum mattis pellentesque id \n"
    "nibh tortor. Placerat vestibulum lectus mauris ultrices eros. Mattis \n"
    "rhoncus urna neque viverra. Vulputate dignissim suspendisse in est. \n"
    "Neque egestas congue quisque egestas diam. Mi proin sed libero enim \n"
    "sed faucibus. Nibh tortor id aliquet lectus .\n");

const uint8_t RoCEv2Test::expected_packet_0[] = {
    0x58, 0x4a, 0xdf, 0x60, 0x32, 0xc5, 0x8b, 0x44, 
    0xd7, 0x3f, 0x10, 0xc7, 0x08, 0x00, 0x45, 0x5f, 
    0x04, 0x70, 0xb1, 0x19, 0x40, 0x00, 0x27, 0x11, 
    0x43, 0x4a, 0x32, 0x0b, 0xad, 0x1d, 0x93, 0x90, 
    0xe8, 0x01, 0xfb, 0xaf, 0x12, 0xb7, 0x04, 0x5c, 
    0x54, 0x41, 0x04, 0x00, 0x75, 0x90, 0x00, 0xa4, 
    0x10, 0x7c, 0x80, 0x2a, 0x08, 0x72, 0x4c, 0x6f, 
    0x72, 0x65, 0x6d, 0x20, 0x69, 0x70, 0x73, 0x75, 
    0x6d, 0x20, 0x64, 0x6f, 0x6c, 0x6f, 0x72, 0x20, 
    0x73, 0x69, 0x74, 0x20, 0x61, 0x6d, 0x65, 0x74, 
    0x2c, 0x20, 0x63, 0x6f, 0x6e, 0x73, 0x65, 0x63, 
    0x74, 0x65, 0x74, 0x75, 0x72, 0x20, 0x61, 0x64, 
    0x69, 0x70, 0x69, 0x73, 0x63, 0x69, 0x6e, 0x67, 
    0x20, 0x65, 0x6c, 0x69, 0x74, 0x2c, 0x20, 0x73, 
    0x65, 0x64, 0x20, 0x64, 0x6f, 0x20, 0x0a, 0x65, 
    0x69, 0x75, 0x73, 0x6d, 0x6f, 0x64, 0x20, 0x74, 
    0x65, 0x6d, 0x70, 0x6f, 0x72, 0x20, 0x69, 0x6e, 
    0x63, 0x69, 0x64, 0x69, 0x64, 0x75, 0x6e, 0x74, 
    0x20, 0x75, 0x74, 0x20, 0x6c, 0x61, 0x62, 0x6f, 
    0x72, 0x65, 0x20, 0x65, 0x74, 0x20, 0x64, 0x6f, 
    0x6c, 0x6f, 0x72, 0x65, 0x20, 0x6d, 0x61, 0x67, 
    0x6e, 0x61, 0x20, 0x61, 0x6c, 0x69, 0x71, 0x75, 
    0x61, 0x2e, 0x20, 0x4e, 0x69, 0x62, 0x68, 0x20, 
    0x0a, 0x69, 0x70, 0x73, 0x75, 0x6d, 0x20, 0x63, 
    0x6f, 0x6e, 0x73, 0x65, 0x71, 0x75, 0x61, 0x74, 
    0x20, 0x6e, 0x69, 0x73, 0x6c, 0x20, 0x76, 0x65, 
    0x6c, 0x20, 0x70, 0x72, 0x65, 0x74, 0x69, 0x75, 
    0x6d, 0x20, 0x6c, 0x65, 0x63, 0x74, 0x75, 0x73, 
    0x2e, 0x20, 0x46, 0x65, 0x72, 0x6d, 0x65, 0x6e, 
    0x74, 0x75, 0x6d, 0x20, 0x70, 0x6f, 0x73, 0x75, 
    0x65, 0x72, 0x65, 0x20, 0x75, 0x72, 0x6e, 0x61, 
    0x20, 0x6e, 0x65, 0x63, 0x20, 0x0a, 0x74, 0x69, 
    0x6e, 0x63, 0x69, 0x64, 0x75, 0x6e, 0x74, 0x20, 
    0x70, 0x72, 0x61, 0x65, 0x73, 0x65, 0x6e, 0x74, 
    0x20, 0x73, 0x65, 0x6d, 0x70, 0x65, 0x72, 0x20, 
    0x66, 0x65, 0x75, 0x67, 0x69, 0x61, 0x74, 0x20, 
    0x6e, 0x69, 0x62, 0x68, 0x20, 0x73, 0x65, 0x64, 
    0x2e, 0x20, 0x4c, 0x6f, 0x72, 0x65, 0x6d, 0x20, 
    0x69, 0x70, 0x73, 0x75, 0x6d, 0x20, 0x64, 0x6f, 
    0x6c, 0x6f, 0x72, 0x20, 0x73, 0x69, 0x74, 0x20, 
    0x61, 0x6d, 0x65, 0x74, 0x20, 0x0a, 0x63, 0x6f, 
    0x6e, 0x73, 0x65, 0x63, 0x74, 0x65, 0x74, 0x75, 
    0x72, 0x20, 0x61, 0x64, 0x69, 0x70, 0x69, 0x73, 
    0x63, 0x69, 0x6e, 0x67, 0x2e, 0x20, 0x56, 0x65, 
    0x6c, 0x69, 0x74, 0x20, 0x65, 0x67, 0x65, 0x73, 
    0x74, 0x61, 0x73, 0x20, 0x64, 0x75, 0x69, 0x20, 
    0x69, 0x64, 0x20, 0x6f, 0x72, 0x6e, 0x61, 0x72, 
    0x65, 0x20, 0x61, 0x72, 0x63, 0x75, 0x20, 0x6f, 
    0x64, 0x69, 0x6f, 0x2e, 0x20, 0x44, 0x75, 0x69, 
    0x20, 0x0a, 0x66, 0x61, 0x75, 0x63, 0x69, 0x62, 
    0x75, 0x73, 0x20, 0x69, 0x6e, 0x20, 0x6f, 0x72, 
    0x6e, 0x61, 0x72, 0x65, 0x20, 0x71, 0x75, 0x61, 
    0x6d, 0x20, 0x76, 0x69, 0x76, 0x65, 0x72, 0x72, 
    0x61, 0x20, 0x6f, 0x72, 0x63, 0x69, 0x2e, 0x20, 
    0x45, 0x74, 0x20, 0x6e, 0x65, 0x74, 0x75, 0x73, 
    0x20, 0x65, 0x74, 0x20, 0x6d, 0x61, 0x6c, 0x65, 
    0x73, 0x75, 0x61, 0x64, 0x61, 0x20, 0x66, 0x61, 
    0x6d, 0x65, 0x73, 0x2e, 0x20, 0x0a, 0x45, 0x67, 
    0x65, 0x74, 0x20, 0x64, 0x75, 0x69, 0x73, 0x20, 
    0x61, 0x74, 0x20, 0x74, 0x65, 0x6c, 0x6c, 0x75, 
    0x73, 0x20, 0x61, 0x74, 0x20, 0x75, 0x72, 0x6e, 
    0x61, 0x2e, 0x20, 0x56, 0x75, 0x6c, 0x70, 0x75, 
    0x74, 0x61, 0x74, 0x65, 0x20, 0x64, 0x69, 0x67, 
    0x6e, 0x69, 0x73, 0x73, 0x69, 0x6d, 0x20, 0x73, 
    0x75, 0x73, 0x70, 0x65, 0x6e, 0x64, 0x69, 0x73, 
    0x73, 0x65, 0x20, 0x69, 0x6e, 0x20, 0x65, 0x73, 
    0x74, 0x2e, 0x20, 0x0a, 0x54, 0x69, 0x6e, 0x63, 
    0x69, 0x64, 0x75, 0x6e, 0x74, 0x20, 0x65, 0x67, 
    0x65, 0x74, 0x20, 0x6e, 0x75, 0x6c, 0x6c, 0x61, 
    0x6d, 0x20, 0x6e, 0x6f, 0x6e, 0x20, 0x6e, 0x69, 
    0x73, 0x69, 0x20, 0x65, 0x73, 0x74, 0x20, 0x73, 
    0x69, 0x74, 0x20, 0x61, 0x6d, 0x65, 0x74, 0x20, 
    0x66, 0x61, 0x63, 0x69, 0x6c, 0x69, 0x73, 0x69, 
    0x73, 0x20, 0x6d, 0x61, 0x67, 0x6e, 0x61, 0x2e, 
    0x20, 0x46, 0x65, 0x72, 0x6d, 0x65, 0x6e, 0x74, 
    0x75, 0x6d, 0x20, 0x0a, 0x64, 0x75, 0x69, 0x20, 
    0x66, 0x61, 0x75, 0x63, 0x69, 0x62, 0x75, 0x73, 
    0x20, 0x69, 0x6e, 0x20, 0x6f, 0x72, 0x6e, 0x61, 
    0x72, 0x65, 0x20, 0x71, 0x75, 0x61, 0x6d, 0x20, 
    0x76, 0x69, 0x76, 0x65, 0x72, 0x72, 0x61, 0x2e, 
    0x20, 0x53, 0x65, 0x6d, 0x70, 0x65, 0x72, 0x20, 
    0x76, 0x69, 0x76, 0x65, 0x72, 0x72, 0x61, 0x20, 
    0x6e, 0x61, 0x6d, 0x20, 0x6c, 0x69, 0x62, 0x65, 
    0x72, 0x6f, 0x20, 0x6a, 0x75, 0x73, 0x74, 0x6f, 
    0x20, 0x0a, 0x6c, 0x61, 0x6f, 0x72, 0x65, 0x65, 
    0x74, 0x20, 0x73, 0x69, 0x74, 0x2e, 0x0a, 0x0a, 
    0x56, 0x69, 0x74, 0x61, 0x65, 0x20, 0x70, 0x72, 
    0x6f, 0x69, 0x6e, 0x20, 0x73, 0x61, 0x67, 0x69, 
    0x74, 0x74, 0x69, 0x73, 0x20, 0x6e, 0x69, 0x73, 
    0x6c, 0x20, 0x72, 0x68, 0x6f, 0x6e, 0x63, 0x75, 
    0x73, 0x20, 0x6d, 0x61, 0x74, 0x74, 0x69, 0x73, 
    0x20, 0x72, 0x68, 0x6f, 0x6e, 0x63, 0x75, 0x73, 
    0x20, 0x75, 0x72, 0x6e, 0x61, 0x20, 0x6e, 0x65, 
    0x71, 0x75, 0x65, 0x2e, 0x20, 0x52, 0x75, 0x74, 
    0x72, 0x75, 0x6d, 0x20, 0x0a, 0x74, 0x65, 0x6c, 
    0x6c, 0x75, 0x73, 0x20, 0x70, 0x65, 0x6c, 0x6c, 
    0x65, 0x6e, 0x74, 0x65, 0x73, 0x71, 0x75, 0x65, 
    0x20, 0x65, 0x75, 0x20, 0x74, 0x69, 0x6e, 0x63, 
    0x69, 0x64, 0x75, 0x6e, 0x74, 0x20, 0x74, 0x6f, 
    0x72, 0x74, 0x6f, 0x72, 0x20, 0x61, 0x6c, 0x69, 
    0x71, 0x75, 0x61, 0x6d, 0x2e, 0x20, 0x47, 0x72, 
    0x61, 0x76, 0x69, 0x64, 0x61, 0x20, 0x61, 0x72, 
    0x63, 0x75, 0x20, 0x61, 0x63, 0x20, 0x0a, 0x74, 
    0x6f, 0x72, 0x74, 0x6f, 0x72, 0x20, 0x64, 0x69, 
    0x67, 0x6e, 0x69, 0x73, 0x73, 0x69, 0x6d, 0x20, 
    0x63, 0x6f, 0x6e, 0x76, 0x61, 0x6c, 0x6c, 0x69, 
    0x73, 0x2e, 0x20, 0x55, 0x72, 0x6e, 0x61, 0x20, 
    0x63, 0x6f, 0x6e, 0x64, 0x69, 0x6d, 0x65, 0x6e, 
    0x74, 0x75, 0x6d, 0x20, 0x6d, 0x61, 0x74, 0x74, 
    0x69, 0x73, 0x20, 0x70, 0x65, 0x6c, 0x6c, 0x65, 
    0x6e, 0x74, 0x65, 0x73, 0x71, 0x75, 0x65, 0x20, 
    0x69, 0x64, 0x20, 0x0a, 0x6e, 0x69, 0x62, 0x68, 
    0x20, 0x74, 0x6f, 0x72, 0x74, 0x6f, 0x72, 0x2e, 
    0x20, 0x50, 0x6c, 0x61, 0x63, 0x65, 0x72, 0x61, 
    0x74, 0x20, 0x76, 0x65, 0x73, 0x74, 0x69, 0x62, 
    0x75, 0x6c, 0x75, 0x6d, 0x20, 0x6c, 0x65, 0x63, 
    0x74, 0x75, 0x73, 0x20, 0x6d, 0x61, 0x75, 0x72, 
    0x69, 0x73, 0x20, 0x75, 0x6c, 0x74, 0x72, 0x69, 
    0x63, 0x65, 0x73, 0x20, 0x65, 0x72, 0x6f, 0x73, 
    0x2e, 0x20, 0x4d, 0x61, 0x74, 0x74, 0x69, 0x73, 
    0x20, 0x0a, 0x72, 0x68, 0x6f, 0x6e, 0x63, 0x75, 
    0x73, 0x20, 0x75, 0x72, 0x6e, 0x61, 0x20, 0x6e, 
    0x65, 0x71, 0x75, 0x65, 0x20, 0x76, 0x69, 0x76, 
    0x65, 0x72, 0x72, 0x61, 0x2e, 0x20, 0x56, 0x75, 
    0x6c, 0x70, 0x75, 0x74, 0x61, 0x74, 0x65, 0x20, 
    0x64, 0x69, 0x67, 0x6e, 0x69, 0x73, 0x73, 0x69, 
    0x6d, 0x20, 0x73, 0x75, 0x73, 0x70, 0x65, 0x6e, 
    0x64, 0x69, 0x73, 0x73, 0x65, 0x20, 0x69, 0x6e, 
    0x20, 0x65, 0x73, 0x74, 0x2e, 0x20, 0x0a, 0x4e, 
    0x65, 0x71, 0x75, 0x65, 0x20, 0x65, 0x67, 0x65, 
    0x73, 0x74, 0x61, 0x73, 0x20, 0x63, 0x6f, 0x6e, 
    0x67, 0x75, 0x65, 0x20, 0x71, 0x75, 0x69, 0x73, 
    0x71, 0x75, 0x65, 0x20, 0x65, 0x67, 0x65, 0x73, 
    0x74, 0x61, 0x73, 0x20, 0x64, 0x69, 0x61, 0x6d, 
    0x2e, 0x20, 0x4d, 0x69, 0x20, 0x70, 0x72, 0x6f, 
    0x69, 0x6e, 0x20, 0x73, 0x65, 0x64, 0x20, 0x6c, 
    0x69, 0x62, 0x65, 0x72, 0x6f, 0x20, 0x65, 0x6e, 
    0x69, 0x6d, 0x20, 0x0a, 0x73, 0x65, 0x64, 0x20, 
    0x66, 0x61, 0x75, 0x63, 0x69, 0x62, 0x75, 0x73, 
    0x2e, 0x20, 0x4e, 0x69, 0x62, 0x68, 0x20, 0x74, 
    0x6f, 0x72, 0x74, 0x6f, 0x72, 0x20, 0x69, 0x64, 
    0x20, 0x61, 0x6c, 0x69, 0x71, 0x75, 0x65, 0x74, 
    0x20, 0x6c, 0x65, 0x63, 0x74, 0x75, 0x73, 0x20, 
    0x2e, 0x0a, 0x00, 0x00, 0x00, 0x00};
        
TEST_F(RoCEv2Test, CreateFullPacket) {
    EthernetII pkt1 = EthernetII() / IP() / UDP() / IB::BTH();
    pkt1 /= RawPDU(payload_0);
    
    pkt1.dst_addr(EthernetII::address_type{"58:4a:df:60:32:c5"});
    pkt1.src_addr(EthernetII::address_type{"8b:44:d7:3f:10:c7"});
    
    auto ip = pkt1.find_pdu<IP>();
    ASSERT_NE(ip, nullptr);

    ip->tos(0x5f);
    ip->id(0xb119);
    ip->flags(IP::DONT_FRAGMENT);
    ip->fragment_offset(0x0);
    ip->ttl(0x27);
    ip->src_addr(IP::address_type{htonl(0x320bad1d)});
    ip->dst_addr(IP::address_type{htonl(0x9390e801)});

    auto udp = ip->find_pdu<UDP>();
    ASSERT_NE(udp, nullptr);
    
    udp->sport(0xfbaf);
    
    auto bth = udp->find_pdu<IB::BTH>();
    ASSERT_NE(bth, nullptr);

    bth->opcode(IB::RC_SEND_ONLY);
    bth->se(0);
    bth->m(0);
    bth->p_key(0x7590);
    bth->destqp(0xa4107cU);
    bth->a(1);
    bth->psn(0x2a0872U);

    ASSERT_NE(bth->inner_pdu(), nullptr);
    
    auto buffer = pkt1.serialize();
    auto pkt1_ip_checksum = ip->checksum();
    auto pkt1_udp_checksum = udp->checksum();
    
    EXPECT_EQ(buffer,
              std::vector<uint8_t>(
                  expected_packet_0,
                  expected_packet_0 + sizeof(expected_packet_0)));

    EthernetII pkt2{buffer.data(), static_cast<uint32_t>(buffer.size())};

    EXPECT_EQ(pkt2.dst_addr(), EthernetII::address_type{"58:4a:df:60:32:c5"});
    EXPECT_EQ(pkt2.src_addr(), EthernetII::address_type{"8b:44:d7:3f:10:c7"});
    EXPECT_EQ(pkt2.payload_type(), 0x800);
    
    ip = pkt2.find_pdu<IP>();
    ASSERT_NE(ip, nullptr);

    EXPECT_EQ(ip->version(), 0x4);
    EXPECT_EQ(ip->head_len(), 0x5);
    EXPECT_EQ(ip->tos(), 0x5f);
    EXPECT_EQ(ip->tot_len(), 20 + 8 + 16 + payload_0.size());
    EXPECT_EQ(ip->id(), 0xb119);
    EXPECT_EQ(bool(ip->flags() & IP::DONT_FRAGMENT), 0x1);
    EXPECT_EQ(bool(ip->flags() & IP::MORE_FRAGMENTS), 0x0);
    EXPECT_EQ(ip->fragment_offset(), 0x0);
    EXPECT_EQ(ip->ttl(), 0x27);
    EXPECT_EQ(ip->protocol(), 0x11);
    EXPECT_EQ(ip->checksum(), pkt1_ip_checksum);
    EXPECT_EQ(ip->src_addr(), IP::address_type{htonl(0x320bad1d)});
    EXPECT_EQ(ip->dst_addr(), IP::address_type{htonl(0x9390e801)});

    udp = ip->find_pdu<UDP>();
    ASSERT_NE(udp, nullptr);
    
    EXPECT_EQ(udp->sport(), 0xfbaf);
    EXPECT_EQ(udp->dport(), 0x12b7);
    EXPECT_EQ(udp->length(), 8 + 16 + payload_0.size());
    EXPECT_EQ(udp->checksum(), pkt1_udp_checksum);
    
    bth = udp->find_pdu<IB::BTH>();
    ASSERT_NE(bth, nullptr);

    EXPECT_EQ(bth->opcode(), IB::RC_SEND_ONLY);
    EXPECT_EQ(bth->se(), 0);
    EXPECT_EQ(bth->m(), 0);
    EXPECT_EQ(bth->padcnt(), 0);
    EXPECT_EQ(bth->tver(), 0);
    EXPECT_EQ(bth->p_key(), 0x7590);
    EXPECT_EQ(bth->destqp(), 0xa4107cU);
    EXPECT_EQ(bth->a(), 1);
    EXPECT_EQ(bth->psn(), 0x2a0872U);
    EXPECT_EQ(bth->icrc(), 0U);

    ASSERT_NE(bth->inner_pdu(), nullptr);
    
    auto payload = dynamic_cast<RawPDU*>(bth->inner_pdu());
    EXPECT_EQ(payload->pdu_type(), PDU::RAW);
    EXPECT_EQ(payload->size(), payload_0.size());
    EXPECT_EQ(payload->inner_pdu(), nullptr);
    EXPECT_EQ(payload->payload(), 
              std::vector<uint8_t>(payload_0.begin(), payload_0.end()));
}

/*
    cfg_hdr : {eth[0], ipv4[0], udp[0], roce[0], bth[0], data[0]}
             toh :                                                   plen : 151 
             toh :                                           chop_plen_to : 0 
          eth[0] : [   0 :   47] :   0 :                               da : 48'hdd 
          eth[0] : [  48 :   95] :   6 :                               sa : 48'h12345678abcd 
          eth[0] : [  96 :  111] :  12 :                            etype : 16'h800 (IPV4)
         ipv4[0] : [ 112 :  115] :  14 :                          version : 4'h4 
         ipv4[0] : [ 116 :  119] :  14 :                              ihl : 4'h5 
         ipv4[0] : [ 120 :  127] :  15 :                              tos : 8'hf9 
         ipv4[0] : [ 128 :  143] :  16 :                     total_length : 16'h6c 
         ipv4[0] : [ 144 :  159] :  18 :                               id : 16'hf7e7 
         ipv4[0] : [ 160 :  160] :  20 :                         reserved : 1'h0 
         ipv4[0] : [ 161 :  161] :  20 :                               df : 1'h0 
         ipv4[0] : [ 162 :  162] :  20 :                               mf : 1'h0 
         ipv4[0] : [ 163 :  175] :  20 :                      frag_offset : 13'h0 
         ipv4[0] : [ 176 :  183] :  22 :                              ttl : 8'h71 
         ipv4[0] : [ 184 :  191] :  23 :                         protocol : 8'h11 (UDP)
         ipv4[0] : [ 192 :  207] :  24 :                         checksum : 16'h6ad9 (GOOD)
         ipv4[0] : [ 208 :  239] :  26 :                            ip_sa : 32'h82726353 
         ipv4[0] : [ 240 :  271] :  30 :                            ip_da : 32'h2 
          udp[0] : [ 272 :  287] :  34 :                          src_prt : 16'hcba9 
          udp[0] : [ 288 :  303] :  36 :                          dst_prt : 16'h12b7 (ROCEV2)
          udp[0] : [ 304 :  319] :  38 :                           length : 16'h58 
          udp[0] : [ 320 :  335] :  40 :                         checksum : 16'h2258 (GOOD)
          bth[0] : [ 336 :  343] :  42 :                           opcode : 8'b100 (RC_SEND_ONLY)
          bth[0] : [ 344 :  344] :  43 :                                S : 1'b0 
          bth[0] : [ 345 :  345] :  43 :                                M : 1'b0 
          bth[0] : [ 346 :  347] :  43 :                           padcnt : 2'h0 
          bth[0] : [ 348 :  351] :  43 :                             tver : 4'h0 
          bth[0] : [ 352 :  367] :  44 :                            p_key : 16'hffff 
          bth[0] : [ 368 :  375] :  46 :                            rsvd0 : 8'h8d 
          bth[0] : [ 376 :  399] :  47 :                           destQP : 24'h41 
          bth[0] : [ 400 :  400] :  50 :                                A : 1'b1 
          bth[0] : [ 401 :  407] :  50 :                            rsvd1 : 7'h62 
          bth[0] : [ 408 :  431] :  51 :                              psn : 24'h2 
          bth[0] : ~~~~~~~~~~ No Extension Transport Header ~~~~~
         data[0] :                                               data_len : 64 (data => b0 ce 95 c0 ..)
         roce[0] : [ 944 :  975] : 118 :                             icrc : 32'h0 (GOOD)
             toh :                                                pad_len : 29 
         pkt_lib :        0   1  2  3  4  5  6  7 |  8  9 10 11 12 13 14 15
         pkt_lib :        ~~~~~~~~~~~~~~~~~~~~~~~~|~~~~~~~~~~~~~~~~~~~~~~~~
         pkt_lib :    0 : 00 00 00 00 00 dd 12 34 | 56 78 ab cd 08 00 45 f9 
         pkt_lib :   16 : 00 6c f7 e7 00 00 71 11 | 6a d9 82 72 63 53 00 00 
         pkt_lib :   32 : 00 02 cb a9 12 b7 00 58 | 22 58 04 00 ff ff 8d 00 
         pkt_lib :   48 : 00 41 e2 00 00 02 b0 ce | 95 c0 65 87 ef cd 40 00 
         pkt_lib :   64 : 00 00 00 00 00 00 10 32 | 54 76 98 ba dc fe 01 23 
         pkt_lib :   80 : 45 67 89 ab cd ef 13 57 | 9b df 02 46 8a ce fe dc 
         pkt_lib :   96 : ba 98 76 54 32 10 ec a8 | 64 20 fd b9 75 31 88 99 
         pkt_lib :  112 : aa bb cc dd ee ff 00 00 | 00 00 58 6c 1e 3f 57 3d 
         pkt_lib :  128 : 53 b9 63 97 8c 53 d3 99 | 1e f1 fd a7 08 8f 09 26 
         pkt_lib :  144 : 8f 60 65 64 ec f7 b7 
         pkt_lib :        ~~~~~~~~~~~~~~~~~~~~~~~~|~~~~~~~~~~~~~~~~~~~~~~~~
         pkt_lib : (Total Len  = 151)
*/
const uint8_t RoCEv2Test::expected_packet_1[] = { 
    0x00, 0x00, 0x00, 0x00, 0x00, 0xdd, 0x12, 0x34,
    0x56, 0x78, 0xab, 0xcd, 0x08, 0x00, 0x45, 0xf9,
    0x00, 0x6c, 0xf7, 0xe7, 0x00, 0x00, 0x71, 0x11,
    0x6a, 0xd9, 0x82, 0x72, 0x63, 0x53, 0x00, 0x00,
    0x00, 0x02, 0xcb, 0xa9, 0x12, 0xb7, 0x00, 0x58,
    0x22, 0x58, 0x04, 0x00, 0xff, 0xff, 0x8d, 0x00,
    0x00, 0x41, 0xe2, 0x00, 0x00, 0x02, 0xb0, 0xce,
    0x95, 0xc0, 0x65, 0x87, 0xef, 0xcd, 0x40, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x32,
    0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0x01, 0x23,
    0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x13, 0x57,
    0x9b, 0xdf, 0x02, 0x46, 0x8a, 0xce, 0xfe, 0xdc,
    0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0xec, 0xa8,
    0x64, 0x20, 0xfd, 0xb9, 0x75, 0x31, 0x88, 0x99,
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x00,
    0x00, 0x00, 0x58, 0x6c, 0x1e, 0x3f, 0x57, 0x3d,
    0x53, 0xb9, 0x63, 0x97, 0x8c, 0x53, 0xd3, 0x99,
    0x1e, 0xf1, 0xfd, 0xa7, 0x08, 0x8f, 0x09, 0x26,
    0x8f, 0x60, 0x65, 0x64, 0xec, 0xf7, 0xb7};

TEST_F(RoCEv2Test, SvPktlib1) {
    EthernetII eth{expected_packet_1, sizeof(expected_packet_1)};

    EXPECT_EQ(eth.dst_addr(), EthernetII::address_type{"00:00:00:00:00:dd"});
    EXPECT_EQ(eth.src_addr(), EthernetII::address_type{"12:34:56:78:ab:cd"});
    EXPECT_EQ(eth.payload_type(), 0x800);
    
    auto ip = eth.find_pdu<IP>();
    ASSERT_NE(ip, nullptr);

    EXPECT_EQ(ip->version(), 0x4);
    EXPECT_EQ(ip->head_len(), 0x5);
    EXPECT_EQ(ip->tos(), 0xf9);
    EXPECT_EQ(ip->tot_len(), 0x6c);
    EXPECT_EQ(ip->id(), 0xf7e7);
    EXPECT_EQ(bool(ip->flags() & IP::DONT_FRAGMENT), 0x0);
    EXPECT_EQ(bool(ip->flags() & IP::MORE_FRAGMENTS), 0x0);
    EXPECT_EQ(ip->fragment_offset(), 0x0);
    EXPECT_EQ(ip->ttl(), 0x71);
    EXPECT_EQ(ip->protocol(), 0x11);
    EXPECT_EQ(ip->checksum(), 0x6ad9);
    EXPECT_EQ(ip->src_addr(), IP::address_type{htonl(0x82726353)});
    EXPECT_EQ(ip->dst_addr(), IP::address_type{htonl(0x00000002)});

    auto udp = ip->find_pdu<UDP>();
    ASSERT_NE(udp, nullptr);
    
    EXPECT_EQ(udp->sport(), 0xcba9);
    EXPECT_EQ(udp->dport(), 0x12b7);
    EXPECT_EQ(udp->length(), 0x58);
    EXPECT_EQ(udp->checksum(), 0x2258);
    
    auto bth = udp->find_pdu<IB::BTH>();
    ASSERT_NE(bth, nullptr);

    EXPECT_EQ(bth->opcode(), IB::RC_SEND_ONLY);
    EXPECT_EQ(bth->se(), 0);
    EXPECT_EQ(bth->m(), 0);
    EXPECT_EQ(bth->padcnt(), 0);
    EXPECT_EQ(bth->tver(), 0);
    EXPECT_EQ(bth->p_key(), 0xffff);
    EXPECT_EQ(bth->destqp(), 0x000041U);
    EXPECT_EQ(bth->a(), 1);
    EXPECT_EQ(bth->psn(), 0x000002U);
    EXPECT_EQ(bth->icrc(), 0U);

    ASSERT_NE(bth->inner_pdu(), nullptr);
    auto payload = dynamic_cast<RawPDU*>(bth->inner_pdu());
    EXPECT_EQ(payload->pdu_type(), PDU::RAW);
    EXPECT_EQ(payload->size(), 64U);
    EXPECT_EQ(payload->inner_pdu(), nullptr);
    
    EXPECT_EQ(payload->payload(),
              std::vector<uint8_t>(expected_packet_1 + 54,
                                   expected_packet_1 + 54 + 64));
}

/*
    cfg_hdr : {eth[0], ipv4[0], udp[0], roce[0], bth[0], data[0]}
             toh :                                                   plen : 62 
             toh :                                           chop_plen_to : 0 
          eth[0] : [   0 :   47] :   0 :                               da : 48'hf49bc1dc4b74 
          eth[0] : [  48 :   95] :   6 :                               sa : 48'hdd 
          eth[0] : [  96 :  111] :  12 :                            etype : 16'h800 (IPV4)
         ipv4[0] : [ 112 :  115] :  14 :                          version : 4'h4 
         ipv4[0] : [ 116 :  119] :  14 :                              ihl : 4'h5 
         ipv4[0] : [ 120 :  127] :  15 :                              tos : 8'h1c 
         ipv4[0] : [ 128 :  143] :  16 :                     total_length : 16'h30 
         ipv4[0] : [ 144 :  159] :  18 :                               id : 16'h0 
         ipv4[0] : [ 160 :  160] :  20 :                         reserved : 1'h0 
         ipv4[0] : [ 161 :  161] :  20 :                               df : 1'h1 
         ipv4[0] : [ 162 :  162] :  20 :                               mf : 1'h0 
         ipv4[0] : [ 163 :  175] :  20 :                      frag_offset : 13'h0 
         ipv4[0] : [ 176 :  183] :  22 :                              ttl : 8'hff 
         ipv4[0] : [ 184 :  191] :  23 :                         protocol : 8'h11 (UDP)
         ipv4[0] : [ 192 :  207] :  24 :                         checksum : 16'h95d9 (GOOD)
         ipv4[0] : [ 208 :  239] :  26 :                            ip_sa : 32'h2 
         ipv4[0] : [ 240 :  271] :  30 :                            ip_da : 32'h82726353 
          udp[0] : [ 272 :  287] :  34 :                          src_prt : 16'h7050 
          udp[0] : [ 288 :  303] :  36 :                          dst_prt : 16'h12b7 (ROCEV2)
          udp[0] : [ 304 :  319] :  38 :                           length : 16'h1c 
          udp[0] : [ 320 :  335] :  40 :                         checksum : 16'h0 (GOOD)
          bth[0] : [ 336 :  343] :  42 :                           opcode : 8'b10001 (RC_ACKNOWLEDGE)
          bth[0] : [ 344 :  344] :  43 :                                S : 1'b0 
          bth[0] : [ 345 :  345] :  43 :                                M : 1'b0 
          bth[0] : [ 346 :  347] :  43 :                           padcnt : 2'h0 
          bth[0] : [ 348 :  351] :  43 :                             tver : 4'h0 
          bth[0] : [ 352 :  367] :  44 :                            p_key : 16'hffff 
          bth[0] : [ 368 :  375] :  46 :                            rsvd0 : 8'h0 
          bth[0] : [ 376 :  399] :  47 :                           destQP : 24'hca1839 
          bth[0] : [ 400 :  400] :  50 :                                A : 1'b0 
          bth[0] : [ 401 :  407] :  50 :                            rsvd1 : 7'h0 
          bth[0] : [ 408 :  431] :  51 :                              psn : 24'h2 
          bth[0] : ~~~~~~~~~~ AETH hdr ~~~~~~~~~~~~~~
          bth[0] : [ 432 :  439] :  54 :                          syndrom : 8'h0 
          bth[0] : [ 440 :  463] :  55 :                              msn : 24'ha9d0bd 
         data[0] :                                               data_len : 0 (data => EMPTY)
         roce[0] : [ 464 :  495] :  58 :                             icrc : 32'h0 (GOOD)
             toh :                                                pad_len : 0 
         pkt_lib :        0   1  2  3  4  5  6  7 |  8  9 10 11 12 13 14 15
         pkt_lib :        ~~~~~~~~~~~~~~~~~~~~~~~~|~~~~~~~~~~~~~~~~~~~~~~~~
         pkt_lib :    0 : f4 9b c1 dc 4b 74 00 00 | 00 00 00 dd 08 00 45 1c 
         pkt_lib :   16 : 00 30 00 00 40 00 ff 11 | 95 d9 00 00 00 02 82 72 
         pkt_lib :   32 : 63 53 70 50 12 b7 00 1c | 00 00 11 00 ff ff 00 ca 
         pkt_lib :   48 : 18 39 00 00 00 02 00 a9 | d0 bd 00 00 00 00 
         pkt_lib :        ~~~~~~~~~~~~~~~~~~~~~~~~|~~~~~~~~~~~~~~~~~~~~~~~~
         pkt_lib : (Total Len  = 62)
*/
const uint8_t RoCEv2Test::expected_packet_2[] = { 
    0xf4, 0x9b, 0xc1, 0xdc, 0x4b, 0x74, 0x00, 0x00,
    0x00, 0x00, 0x00, 0xdd, 0x08, 0x00, 0x45, 0x1c,
    0x00, 0x30, 0x00, 0x00, 0x40, 0x00, 0xff, 0x11,
    0x95, 0xd9, 0x00, 0x00, 0x00, 0x02, 0x82, 0x72,
    0x63, 0x53, 0x70, 0x50, 0x12, 0xb7, 0x00, 0x1c,
    0x00, 0x00, 0x11, 0x00, 0xff, 0xff, 0x00, 0xca,
    0x18, 0x39, 0x00, 0x00, 0x00, 0x02, 0x00, 0xa9,
    0xd0, 0xbd, 0x00, 0x00, 0x00, 0x00};

TEST_F(RoCEv2Test, SvPktlib2) {
    EthernetII eth{expected_packet_2, sizeof(expected_packet_2)};

    EXPECT_EQ(eth.dst_addr(), EthernetII::address_type{"f4:9b:c1:dc:4b:74"});
    EXPECT_EQ(eth.src_addr(), EthernetII::address_type{"00:00:00:00:00:dd"});
    EXPECT_EQ(eth.payload_type(), 0x800);
    
    auto ip = eth.find_pdu<IP>();
    ASSERT_NE(ip, nullptr);

    EXPECT_EQ(ip->version(), 0x4);
    EXPECT_EQ(ip->head_len(), 0x5);
    EXPECT_EQ(ip->tos(), 0x1c);
    EXPECT_EQ(ip->tot_len(), 0x30);
    EXPECT_EQ(ip->id(), 0x0);
    EXPECT_EQ(bool(ip->flags() & IP::DONT_FRAGMENT), 0x1);
    EXPECT_EQ(bool(ip->flags() & IP::MORE_FRAGMENTS), 0x0);
    EXPECT_EQ(ip->fragment_offset(), 0x0);
    EXPECT_EQ(ip->ttl(), 0xff);
    EXPECT_EQ(ip->protocol(), 0x11);
    EXPECT_EQ(ip->checksum(), 0x95d9);
    EXPECT_EQ(ip->src_addr(), IP::address_type{htonl(0x00000002)});
    EXPECT_EQ(ip->dst_addr(), IP::address_type{htonl(0x82726353)});
    
    auto udp = ip->find_pdu<UDP>();
    ASSERT_NE(udp, nullptr);
    
    EXPECT_EQ(udp->sport(), 0x7050);
    EXPECT_EQ(udp->dport(), 0x12b7);
    EXPECT_EQ(udp->length(), 0x1c);
    EXPECT_EQ(udp->checksum(), 0x0);
    
    auto bth = udp->find_pdu<IB::BTH>();
    ASSERT_NE(bth, nullptr);

    EXPECT_EQ(bth->opcode(), IB::RC_ACKNOWLEDGE);
    EXPECT_EQ(bth->se(), 0);
    EXPECT_EQ(bth->m(), 0);
    EXPECT_EQ(bth->padcnt(), 0);
    EXPECT_EQ(bth->tver(), 0);
    EXPECT_EQ(bth->p_key(), 0xffff);
    EXPECT_EQ(bth->destqp(), 0xca1839U);
    EXPECT_EQ(bth->a(), 0);
    EXPECT_EQ(bth->psn(), 0x000002U);
    EXPECT_EQ(bth->syndrome(), 0);
    EXPECT_EQ(bth->msn(), 0xa9d0bdU);
    EXPECT_EQ(bth->icrc(), 0U);
    
    ASSERT_EQ(bth->inner_pdu(), nullptr);
}

/*
    cfg_hdr : {eth[0], ipv4[0], udp[0], roce[0], bth[0], data[0]}
             toh :                                                   plen : 126 
             toh :                                           chop_plen_to : 0 
          eth[0] : [   0 :   47] :   0 :                               da : 48'hf49bc1dc4b74 
          eth[0] : [  48 :   95] :   6 :                               sa : 48'hdd 
          eth[0] : [  96 :  111] :  12 :                            etype : 16'h800 (IPV4)
         ipv4[0] : [ 112 :  115] :  14 :                          version : 4'h4 
         ipv4[0] : [ 116 :  119] :  14 :                              ihl : 4'h5 
         ipv4[0] : [ 120 :  127] :  15 :                              tos : 8'h1c 
         ipv4[0] : [ 128 :  143] :  16 :                     total_length : 16'h6c 
         ipv4[0] : [ 144 :  159] :  18 :                               id : 16'h0 
         ipv4[0] : [ 160 :  160] :  20 :                         reserved : 1'h0 
         ipv4[0] : [ 161 :  161] :  20 :                               df : 1'h1 
         ipv4[0] : [ 162 :  162] :  20 :                               mf : 1'h0 
         ipv4[0] : [ 163 :  175] :  20 :                      frag_offset : 13'h0 
         ipv4[0] : [ 176 :  183] :  22 :                              ttl : 8'hff 
         ipv4[0] : [ 184 :  191] :  23 :                         protocol : 8'h11 (UDP)
         ipv4[0] : [ 192 :  207] :  24 :                         checksum : 16'h959d (GOOD)
         ipv4[0] : [ 208 :  239] :  26 :                            ip_sa : 32'h2 
         ipv4[0] : [ 240 :  271] :  30 :                            ip_da : 32'h82726353 
          udp[0] : [ 272 :  287] :  34 :                          src_prt : 16'h7050 
          udp[0] : [ 288 :  303] :  36 :                          dst_prt : 16'h12b7 (ROCEV2)
          udp[0] : [ 304 :  319] :  38 :                           length : 16'h1c 
          udp[0] : [ 320 :  335] :  40 :                         checksum : 16'h0 (GOOD)
          bth[0] : [ 336 :  343] :  42 :                           opcode : 8'b100 (RC_SEND_ONLY)
          bth[0] : [ 344 :  344] :  43 :                                S : 1'b0 
          bth[0] : [ 345 :  345] :  43 :                                M : 1'b0 
          bth[0] : [ 346 :  347] :  43 :                           padcnt : 2'h0 
          bth[0] : [ 348 :  351] :  43 :                             tver : 4'h0 
          bth[0] : [ 352 :  367] :  44 :                            p_key : 16'hffff 
          bth[0] : [ 368 :  375] :  46 :                            rsvd0 : 8'h0 
          bth[0] : [ 376 :  399] :  47 :                           destQP : 24'hca1839 
          bth[0] : [ 400 :  400] :  50 :                                A : 1'b1 
          bth[0] : [ 401 :  407] :  50 :                            rsvd1 : 7'h0 
          bth[0] : [ 408 :  431] :  51 :                              psn : 24'h3e 
          bth[0] : ~~~~~~~~~~ No Extension Transport Header ~~~~~
         data[0] :                                               data_len : 68 (data => 00 01 02 03 ..)
         roce[0] : [ 976 : 1007] : 122 :                             icrc : 32'h0 (GOOD)
             toh :                                                pad_len : 0 
         pkt_lib :        0   1  2  3  4  5  6  7 |  8  9 10 11 12 13 14 15
         pkt_lib :        ~~~~~~~~~~~~~~~~~~~~~~~~|~~~~~~~~~~~~~~~~~~~~~~~~
         pkt_lib :    0 : f4 9b c1 dc 4b 74 00 00 | 00 00 00 dd 08 00 45 1c 
         pkt_lib :   16 : 00 6c 00 00 40 00 ff 11 | 95 9d 00 00 00 02 82 72 
         pkt_lib :   32 : 63 53 70 50 12 b7 00 1c | 00 00 04 00 ff ff 00 ca 
         pkt_lib :   48 : 18 39 80 00 00 3e 00 01 | 02 03 04 05 06 07 08 09 
         pkt_lib :   64 : 0a 0b 0c 0d 0e 0f 10 11 | 12 13 14 15 16 17 18 19 
         pkt_lib :   80 : 1a 1b 1c 1d 1e 1f 20 21 | 22 23 24 25 26 27 28 29 
         pkt_lib :   96 : 2a 2b 2c 2d 2e 2f 30 31 | 32 33 34 35 36 37 38 39 
         pkt_lib :  112 : 3a 3b 3c 3d 3e 3f 00 00 | 00 00 00 00 00 00 
         pkt_lib :        ~~~~~~~~~~~~~~~~~~~~~~~~|~~~~~~~~~~~~~~~~~~~~~~~~
         pkt_lib : (Total Len  = 126)
*/
const uint8_t RoCEv2Test::expected_packet_3[] = {
    0xf4, 0x9b, 0xc1, 0xdc, 0x4b, 0x74, 0x00, 0x00,
    0x00, 0x00, 0x00, 0xdd, 0x08, 0x00, 0x45, 0x1c,
    0x00, 0x6c, 0x00, 0x00, 0x40, 0x00, 0xff, 0x11,
    0x95, 0x9d, 0x00, 0x00, 0x00, 0x02, 0x82, 0x72,
    0x63, 0x53, 0x70, 0x50, 0x12, 0xb7, 0x00, 0x1c,
    0x00, 0x00, 0x04, 0x00, 0xff, 0xff, 0x00, 0xca,
    0x18, 0x39, 0x80, 0x00, 0x00, 0x3e, 0x00, 0x01,
    0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
    0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11,
    0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
    0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21,
    0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
    0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31,
    0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
    0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

TEST_F(RoCEv2Test, SvPktlib3) {
    EthernetII eth{expected_packet_3, sizeof(expected_packet_3)};

    EXPECT_EQ(eth.dst_addr(), EthernetII::address_type{"f4:9b:c1:dc:4b:74"});
    EXPECT_EQ(eth.src_addr(), EthernetII::address_type{"00:00:00:00:00:dd"});
    EXPECT_EQ(eth.payload_type(), 0x800);
    
    auto ip = eth.find_pdu<IP>();
    ASSERT_NE(ip, nullptr);

    EXPECT_EQ(ip->version(), 0x4);
    EXPECT_EQ(ip->head_len(), 0x5);
    EXPECT_EQ(ip->tos(), 0x1c);
    EXPECT_EQ(ip->tot_len(), 0x6c);
    EXPECT_EQ(ip->id(), 0);
    EXPECT_EQ(bool(ip->flags() & IP::DONT_FRAGMENT), 1);
    EXPECT_EQ(bool(ip->flags() & IP::MORE_FRAGMENTS), 0);
    EXPECT_EQ(ip->fragment_offset(), 0x0);
    EXPECT_EQ(ip->ttl(), 0xff);
    EXPECT_EQ(ip->protocol(), 0x11);
    EXPECT_EQ(ip->checksum(), 0x959d);
    EXPECT_EQ(ip->src_addr(), IP::address_type{htonl(0x00000002)});
    EXPECT_EQ(ip->dst_addr(), IP::address_type{htonl(0x82726353)});
    
    auto udp = ip->find_pdu<UDP>();
    ASSERT_NE(udp, nullptr);
    
    EXPECT_EQ(udp->sport(), 0x7050);
    EXPECT_EQ(udp->dport(), 0x12b7);
    EXPECT_EQ(udp->length(), 0x1c);
    EXPECT_EQ(udp->checksum(), 0x0000);
    
    auto bth = udp->find_pdu<IB::BTH>();
    ASSERT_NE(bth, nullptr);

    EXPECT_EQ(bth->opcode(), IB::RC_SEND_ONLY);
    EXPECT_EQ(bth->se(), 0);
    EXPECT_EQ(bth->m(), 0);
    EXPECT_EQ(bth->padcnt(), 0);
    EXPECT_EQ(bth->tver(), 0);
    EXPECT_EQ(bth->p_key(), 0xffff);
    EXPECT_EQ(bth->destqp(), 0xca1839U);
    EXPECT_EQ(bth->a(), 1);
    EXPECT_EQ(bth->psn(), 0x00003eU);
    EXPECT_EQ(bth->icrc(), 0U);
    
    ASSERT_NE(bth->inner_pdu(), nullptr);
    auto payload = dynamic_cast<RawPDU*>(bth->inner_pdu());
    EXPECT_EQ(payload->pdu_type(), PDU::RAW);
    EXPECT_EQ(payload->size(), 64U);
    EXPECT_EQ(payload->inner_pdu(), nullptr);
    
    EXPECT_EQ(payload->payload(),
              std::vector<uint8_t>(expected_packet_3 + 54,
                                   expected_packet_3 + 54 + 64));
};

/*
    cfg_hdr : {eth[0], ipv4[0], udp[0], roce[0], bth[0], data[0]}
             toh :                                                   plen : 81 
             toh :                                           chop_plen_to : 0 
          eth[0] : [   0 :   47] :   0 :                               da : 48'hdd 
          eth[0] : [  48 :   95] :   6 :                               sa : 48'h12345678abcd 
          eth[0] : [  96 :  111] :  12 :                            etype : 16'h800 (IPV4)
         ipv4[0] : [ 112 :  115] :  14 :                          version : 4'h4 
         ipv4[0] : [ 116 :  119] :  14 :                              ihl : 4'h5 
         ipv4[0] : [ 120 :  127] :  15 :                              tos : 8'h4b 
         ipv4[0] : [ 128 :  143] :  16 :                     total_length : 16'h30 
         ipv4[0] : [ 144 :  159] :  18 :                               id : 16'hf7e7 
         ipv4[0] : [ 160 :  160] :  20 :                         reserved : 1'h0 
         ipv4[0] : [ 161 :  161] :  20 :                               df : 1'h0 
         ipv4[0] : [ 162 :  162] :  20 :                               mf : 1'h0 
         ipv4[0] : [ 163 :  175] :  20 :                      frag_offset : 13'h0 
         ipv4[0] : [ 176 :  183] :  22 :                              ttl : 8'h10 
         ipv4[0] : [ 184 :  191] :  23 :                         protocol : 8'h11 (UDP)
         ipv4[0] : [ 192 :  207] :  24 :                         checksum : 16'hccc3 (GOOD)
         ipv4[0] : [ 208 :  239] :  26 :                            ip_sa : 32'h82726353 
         ipv4[0] : [ 240 :  271] :  30 :                            ip_da : 32'h2 
          udp[0] : [ 272 :  287] :  34 :                          src_prt : 16'hcba9 
          udp[0] : [ 288 :  303] :  36 :                          dst_prt : 16'h12b7 (ROCEV2)
          udp[0] : [ 304 :  319] :  38 :                           length : 16'h1c 
          udp[0] : [ 320 :  335] :  40 :                         checksum : 16'h3a0d (GOOD)
          bth[0] : [ 336 :  343] :  42 :                           opcode : 8'b10001 (RC_ACKNOWLEDGE)
          bth[0] : [ 344 :  344] :  43 :                                S : 1'b0 
          bth[0] : [ 345 :  345] :  43 :                                M : 1'b0 
          bth[0] : [ 346 :  347] :  43 :                           padcnt : 2'h0 
          bth[0] : [ 348 :  351] :  43 :                             tver : 4'h0 
          bth[0] : [ 352 :  367] :  44 :                            p_key : 16'hffff 
          bth[0] : [ 368 :  375] :  46 :                            rsvd0 : 8'h8d 
          bth[0] : [ 376 :  399] :  47 :                           destQP : 24'h41 
          bth[0] : [ 400 :  400] :  50 :                                A : 1'b0 
          bth[0] : [ 401 :  407] :  50 :                            rsvd1 : 7'h48 
          bth[0] : [ 408 :  431] :  51 :                              psn : 24'h3e 
          bth[0] : ~~~~~~~~~~ AETH hdr ~~~~~~~~~~~~~~
          bth[0] : [ 432 :  439] :  54 :                          syndrom : 8'h1b 
          bth[0] : [ 440 :  463] :  55 :                              msn : 24'h1 
         data[0] :                                               data_len : 0 (data => EMPTY)
         roce[0] : [ 464 :  495] :  58 :                             icrc : 32'h0 (GOOD)
             toh :                                                pad_len : 19 
         pkt_lib :        0   1  2  3  4  5  6  7 |  8  9 10 11 12 13 14 15
         pkt_lib :        ~~~~~~~~~~~~~~~~~~~~~~~~|~~~~~~~~~~~~~~~~~~~~~~~~
         pkt_lib :    0 : 00 00 00 00 00 dd 12 34 | 56 78 ab cd 08 00 45 4b 
         pkt_lib :   16 : 00 30 f7 e7 00 00 10 11 | cc c3 82 72 63 53 00 00 
         pkt_lib :   32 : 00 02 cb a9 12 b7 00 1c | 3a 0d 11 00 ff ff 8d 00 
         pkt_lib :   48 : 00 41 48 00 00 3e 1b 00 | 00 01 00 00 00 00 a4 c3 
         pkt_lib :   64 : 2b 49 14 60 c5 16 36 17 | be b8 63 de e7 0d 9a e0 
         pkt_lib :   80 : d3 
         pkt_lib :        ~~~~~~~~~~~~~~~~~~~~~~~~|~~~~~~~~~~~~~~~~~~~~~~~~
         pkt_lib : (Total Len  = 81)
*/
const uint8_t RoCEv2Test::expected_packet_4[] = { 
    0x00, 0x00, 0x00, 0x00, 0x00, 0xdd, 0x12, 0x34,
    0x56, 0x78, 0xab, 0xcd, 0x08, 0x00, 0x45, 0x4b,
    0x00, 0x30, 0xf7, 0xe7, 0x00, 0x00, 0x10, 0x11,
    0xcc, 0xc3, 0x82, 0x72, 0x63, 0x53, 0x00, 0x00,
    0x00, 0x02, 0xcb, 0xa9, 0x12, 0xb7, 0x00, 0x1c,
    0x3a, 0x0d, 0x11, 0x00, 0xff, 0xff, 0x8d, 0x00,
    0x00, 0x41, 0x48, 0x00, 0x00, 0x3e, 0x1b, 0x00,
    0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0xa4, 0xc3,
    0x2b, 0x49, 0x14, 0x60, 0xc5, 0x16, 0x36, 0x17,
    0xbe, 0xb8, 0x63, 0xde, 0xe7, 0x0d, 0x9a, 0xe0,
    0xd3};

TEST_F(RoCEv2Test, SvPktlib4) {
    EthernetII eth{expected_packet_4, sizeof(expected_packet_4)};

    EXPECT_EQ(eth.dst_addr(), EthernetII::address_type{"00:00:00:00:00:dd"});
    EXPECT_EQ(eth.src_addr(), EthernetII::address_type{"12:34:56:78:ab:cd"});
    EXPECT_EQ(eth.payload_type(), 0x800);
    
    auto ip = eth.find_pdu<IP>();
    ASSERT_NE(ip, nullptr);

    EXPECT_EQ(ip->version(), 0x4);
    EXPECT_EQ(ip->head_len(), 0x5);
    EXPECT_EQ(ip->tos(), 0x4b);
    EXPECT_EQ(ip->tot_len(), 0x30);
    EXPECT_EQ(ip->id(), 0xf7e7);
    EXPECT_EQ(bool(ip->flags() & IP::DONT_FRAGMENT), 0x0);
    EXPECT_EQ(bool(ip->flags() & IP::MORE_FRAGMENTS), 0x0);
    EXPECT_EQ(ip->fragment_offset(), 0x0);
    EXPECT_EQ(ip->ttl(), 0x10);
    EXPECT_EQ(ip->protocol(), 0x11);
    EXPECT_EQ(ip->checksum(), 0xccc3);
    EXPECT_EQ(ip->src_addr(), IP::address_type{htonl(0x82726353)});
    EXPECT_EQ(ip->dst_addr(), IP::address_type{htonl(0x00000002)});
    
    auto udp = ip->find_pdu<UDP>();
    ASSERT_NE(udp, nullptr);
    
    EXPECT_EQ(udp->sport(), 0xcba9);
    EXPECT_EQ(udp->dport(), 0x12b7);
    EXPECT_EQ(udp->length(), 0x1c);
    EXPECT_EQ(udp->checksum(), 0x3a0d);

    auto bth = udp->find_pdu<IB::BTH>();
    ASSERT_NE(bth, nullptr);

    EXPECT_EQ(bth->opcode(), IB::RC_ACKNOWLEDGE);
    EXPECT_EQ(bth->se(), 0);
    EXPECT_EQ(bth->m(), 0);
    EXPECT_EQ(bth->padcnt(), 0);
    EXPECT_EQ(bth->tver(), 0);
    EXPECT_EQ(bth->p_key(), 0xffff);
    EXPECT_EQ(bth->destqp(), 0x000041U);
    EXPECT_EQ(bth->a(), 0);
    EXPECT_EQ(bth->psn(), 0x00003eU);
    EXPECT_EQ(bth->syndrome(), 0x1b);
    EXPECT_EQ(bth->msn(), 0x000001U);
    EXPECT_EQ(bth->icrc(), 0U);
    
    ASSERT_EQ(bth->inner_pdu(), nullptr);
};

/*
    cfg_hdr : {eth[0], ipv4[0], udp[0], roce[0], bth[0], data[0]}
             toh :                                                   plen : 62 
             toh :                                           chop_plen_to : 0 
          eth[0] : [   0 :   47] :   0 :                               da : 48'hf49bc1dc4b74 
          eth[0] : [  48 :   95] :   6 :                               sa : 48'hdd 
          eth[0] : [  96 :  111] :  12 :                            etype : 16'h800 (IPV4)
         ipv4[0] : [ 112 :  115] :  14 :                          version : 4'h4 
         ipv4[0] : [ 116 :  119] :  14 :                              ihl : 4'h5 
         ipv4[0] : [ 120 :  127] :  15 :                              tos : 8'h1c 
         ipv4[0] : [ 128 :  143] :  16 :                     total_length : 16'h30 
         ipv4[0] : [ 144 :  159] :  18 :                               id : 16'h0 
         ipv4[0] : [ 160 :  160] :  20 :                         reserved : 1'h0 
         ipv4[0] : [ 161 :  161] :  20 :                               df : 1'h1 
         ipv4[0] : [ 162 :  162] :  20 :                               mf : 1'h0 
         ipv4[0] : [ 163 :  175] :  20 :                      frag_offset : 13'h0 
         ipv4[0] : [ 176 :  183] :  22 :                              ttl : 8'hff 
         ipv4[0] : [ 184 :  191] :  23 :                         protocol : 8'h11 (UDP)
         ipv4[0] : [ 192 :  207] :  24 :                         checksum : 16'h95d9 (GOOD)
         ipv4[0] : [ 208 :  239] :  26 :                            ip_sa : 32'h2 
         ipv4[0] : [ 240 :  271] :  30 :                            ip_da : 32'h82726353 
          udp[0] : [ 272 :  287] :  34 :                          src_prt : 16'h7050 
          udp[0] : [ 288 :  303] :  36 :                          dst_prt : 16'h12b7 (ROCEV2)
          udp[0] : [ 304 :  319] :  38 :                           length : 16'h1c 
          udp[0] : [ 320 :  335] :  40 :                         checksum : 16'h0 (GOOD)
          bth[0] : [ 336 :  343] :  42 :                           opcode : 8'b10001 (RC_ACKNOWLEDGE)
          bth[0] : [ 344 :  344] :  43 :                                S : 1'b0 
          bth[0] : [ 345 :  345] :  43 :                                M : 1'b0 
          bth[0] : [ 346 :  347] :  43 :                           padcnt : 2'h0 
          bth[0] : [ 348 :  351] :  43 :                             tver : 4'h0 
          bth[0] : [ 352 :  367] :  44 :                            p_key : 16'hffff 
          bth[0] : [ 368 :  375] :  46 :                            rsvd0 : 8'h0 
          bth[0] : [ 376 :  399] :  47 :                           destQP : 24'hca1839 
          bth[0] : [ 400 :  400] :  50 :                                A : 1'b0 
          bth[0] : [ 401 :  407] :  50 :                            rsvd1 : 7'h0 
          bth[0] : [ 408 :  431] :  51 :                              psn : 24'h2 
          bth[0] : ~~~~~~~~~~ AETH hdr ~~~~~~~~~~~~~~
          bth[0] : [ 432 :  439] :  54 :                          syndrom : 8'h0 
          bth[0] : [ 440 :  463] :  55 :                              msn : 24'ha9d0bd 
         data[0] :                                               data_len : 0 (data => EMPTY)
         roce[0] : [ 464 :  495] :  58 :                             icrc : 32'h0 (GOOD)
             toh :                                                pad_len : 0 
         pkt_lib :        0   1  2  3  4  5  6  7 |  8  9 10 11 12 13 14 15
         pkt_lib :        ~~~~~~~~~~~~~~~~~~~~~~~~|~~~~~~~~~~~~~~~~~~~~~~~~
         pkt_lib :    0 : f4 9b c1 dc 4b 74 00 00 | 00 00 00 dd 08 00 45 1c 
         pkt_lib :   16 : 00 30 00 00 40 00 ff 11 | 95 d9 00 00 00 02 82 72 
         pkt_lib :   32 : 63 53 70 50 12 b7 00 1c | 00 00 11 00 ff ff 00 ca 
         pkt_lib :   48 : 18 39 00 00 00 02 00 a9 | d0 bd 00 00 00 00 
         pkt_lib :        ~~~~~~~~~~~~~~~~~~~~~~~~|~~~~~~~~~~~~~~~~~~~~~~~~
         pkt_lib : (Total Len  = 62)
*/
const uint8_t RoCEv2Test::expected_packet_5[] = { 
    0xf4, 0x9b, 0xc1, 0xdc, 0x4b, 0x74, 0x00, 0x00,
    0x00, 0x00, 0x00, 0xdd, 0x08, 0x00, 0x45, 0x1c,
    0x00, 0x30, 0x00, 0x00, 0x40, 0x00, 0xff, 0x11,
    0x95, 0xd9, 0x00, 0x00, 0x00, 0x02, 0x82, 0x72,
    0x63, 0x53, 0x70, 0x50, 0x12, 0xb7, 0x00, 0x1c,
    0x00, 0x00, 0x11, 0x00, 0xff, 0xff, 0x00, 0xca,
    0x18, 0x39, 0x00, 0x00, 0x00, 0x02, 0x00, 0xa9,
    0xd0, 0xbd, 0x00, 0x00, 0x00, 0x00};

TEST_F(RoCEv2Test, SvPktlib5) {
    EthernetII eth{expected_packet_5, sizeof(expected_packet_5)};
    
    EXPECT_EQ(eth.dst_addr(), EthernetII::address_type{"f4:9b:c1:dc:4b:74"});
    EXPECT_EQ(eth.src_addr(), EthernetII::address_type{"00:00:00:00:00:dd"});
    EXPECT_EQ(eth.payload_type(), 0x800);
    
    auto ip = eth.find_pdu<IP>();
    ASSERT_NE(ip, nullptr);
    
    EXPECT_EQ(ip->version(), 0x4);
    EXPECT_EQ(ip->head_len(), 0x5);
    EXPECT_EQ(ip->tos(), 0x1c);
    EXPECT_EQ(ip->tot_len(), 0x30);
    EXPECT_EQ(ip->id(), 0);
    EXPECT_EQ(bool(ip->flags() & IP::DONT_FRAGMENT), 1);
    EXPECT_EQ(bool(ip->flags() & IP::MORE_FRAGMENTS), 0);
    EXPECT_EQ(ip->fragment_offset(), 0x0);
    EXPECT_EQ(ip->ttl(), 0xff);
    EXPECT_EQ(ip->protocol(), 0x11);
    EXPECT_EQ(ip->checksum(), 0x95d9);
    EXPECT_EQ(ip->src_addr(), IP::address_type{htonl(0x00000002)});
    EXPECT_EQ(ip->dst_addr(), IP::address_type{htonl(0x82726353)});
    
    auto udp = ip->find_pdu<UDP>();
    ASSERT_NE(udp, nullptr);
    
    EXPECT_EQ(udp->sport(), 0x7050);
    EXPECT_EQ(udp->dport(), 0x12b7);
    EXPECT_EQ(udp->length(), 0x1c);
    EXPECT_EQ(udp->checksum(), 0x0000);
    
    auto bth = udp->find_pdu<IB::BTH>();
    ASSERT_NE(bth, nullptr);
    
    EXPECT_EQ(bth->opcode(), IB::RC_ACKNOWLEDGE);
    EXPECT_EQ(bth->se(), 0);
    EXPECT_EQ(bth->m(), 0);
    EXPECT_EQ(bth->padcnt(), 0);
    EXPECT_EQ(bth->tver(), 0);
    EXPECT_EQ(bth->p_key(), 0xffff);
    EXPECT_EQ(bth->destqp(), 0xca1839U);
    EXPECT_EQ(bth->a(), 0);
    EXPECT_EQ(bth->psn(), 0x000002U);
    EXPECT_EQ(bth->syndrome(), 0x00);
    EXPECT_EQ(bth->msn(), 0xa9d0bdU);
    EXPECT_EQ(bth->icrc(), 0U);
    
    ASSERT_EQ(bth->inner_pdu(), nullptr);
};
