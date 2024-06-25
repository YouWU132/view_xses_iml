#include <string>
#include <iostream>
#include <pcap.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

#include "constants.h"
#include "utils.h"
#include "moldudp64_protocol.h"
#include "itch_protocol.h"

/**
 * message: an atomic unit of info
 * session: a sequence of messages
 * packet:
 *       header: session + sequence number + message count (start from 0: 10+8+2)
 *       payload (a series of message blocks): message lenth + message data （start from last message block end: 2+? for each message)
 */

using namespace Midas::XSES::ITCH;


std::string decode(const Midas::XSES::ITCH::MessageInfo *msgInfo)
{
    // printf("message data one by one:\n");
    /** message type is the 1st byte of message data */
    // for (auto ptr = msgInfo; ptr; ++ptr)
    // {
    //     printf("%x ", *ptr);
    // }
    // printf("\n");
    switch (msgInfo->get_message_type())
    {
        case Midas::XSES::ITCH::MessageType::Seconds:
        {
            const Midas::XSES::ITCH::Seconds *feed = reinterpret_cast<const Midas::XSES::ITCH::Seconds *>(msgInfo);
            return feed->to_string();
        }
        case Midas::XSES::ITCH::MessageType::OrderBookDirectory:
        {
            const Midas::XSES::ITCH::OrderBookDirectory *feed = reinterpret_cast<const Midas::XSES::ITCH::OrderBookDirectory *>(msgInfo);
            return feed->to_string();
        }
        case Midas::XSES::ITCH::MessageType::CombinationOrderBookDirectory:
        {
            const Midas::XSES::ITCH::CombinationOrderBookLeg *feed = reinterpret_cast<const Midas::XSES::ITCH::CombinationOrderBookLeg *>(msgInfo);
            return feed->to_string();
        }
        case Midas::XSES::ITCH::MessageType::TickSize:
        {
            const Midas::XSES::ITCH::TickSizeTableEntry *feed = reinterpret_cast<const Midas::XSES::ITCH::TickSizeTableEntry *>(msgInfo);
            return feed->to_string();
        }
        case Midas::XSES::ITCH::MessageType::SystemEvent:
        {
            const Midas::XSES::ITCH::SystemEvent *feed = reinterpret_cast<const Midas::XSES::ITCH::SystemEvent *>(msgInfo);
            return feed->to_string();
        }
        case Midas::XSES::ITCH::MessageType::OrderBookState:
        {
            const Midas::XSES::ITCH::OrderBookState *feed = reinterpret_cast<const Midas::XSES::ITCH::OrderBookState *>(msgInfo);
            return feed->to_string();
        }
        case Midas::XSES::ITCH::MessageType::AddOrder:
        {
            const Midas::XSES::ITCH::AddOrder *feed = reinterpret_cast<const Midas::XSES::ITCH::AddOrder *>(msgInfo);
            return feed->to_string();
        }
        case Midas::XSES::ITCH::MessageType::OrderExecuted:
        {
            const Midas::XSES::ITCH::OrderExecuted *feed = reinterpret_cast<const Midas::XSES::ITCH::OrderExecuted *>(msgInfo);
            return feed->to_string();
        }
        case Midas::XSES::ITCH::MessageType::OrderExecutedWithPrice:
        {
            const Midas::XSES::ITCH::OrderExecutedWithPrice *feed = reinterpret_cast<const Midas::XSES::ITCH::OrderExecutedWithPrice *>(msgInfo);
            return feed->to_string();
        }
        case Midas::XSES::ITCH::MessageType::OrderReplace:
        {
            // this should never execute
            const Midas::XSES::ITCH::OrderReplace *feed = reinterpret_cast<const Midas::XSES::ITCH::OrderReplace *>(msgInfo);
            return feed->to_string();
        }
        case Midas::XSES::ITCH::MessageType::OrderDelete:
        {
            const Midas::XSES::ITCH::OrderDelete *feed = reinterpret_cast<const Midas::XSES::ITCH::OrderDelete *>(msgInfo);
            return feed->to_string();
        }
        case Midas::XSES::ITCH::MessageType::TradeMessageIdentifier:
        {
            const Midas::XSES::ITCH::Trade *feed = reinterpret_cast<const Midas::XSES::ITCH::Trade *>(msgInfo);
            return feed->to_string();
        }
        case Midas::XSES::ITCH::MessageType::EquilibriumPriceUpdate:
        {
            const Midas::XSES::ITCH::EquilibriumPriceUpdate *feed = reinterpret_cast<const Midas::XSES::ITCH::EquilibriumPriceUpdate *>(msgInfo);
            return feed->to_string();
        }
        default:
        {
            return "message type not matched";
        }
    }
}

void callback(u_char *additional_args, const struct pcap_pkthdr *hdr, const u_char *packet)
{
    // std::cout << "\na callback called" << std::endl;

    /** Data Link, Ethernet: frame = frame header + frame data */
    // viewdone: how do we know we should compare pkt_hdr->protocal with IPPROTO_UDP, compare eth_hdr->h_proto with ETH_P_IP
    const ethhdr *frame_hdr = reinterpret_cast<const ethhdr *>(packet);
    // viewdone: ETH_P_IP is defined as 2 byte, but stored as 4 byte, how to specify its data type??? -> static_cast<uint16_t>
    if (big_endian_to_host(frame_hdr->h_proto) != static_cast<uint16_t>(ETH_P_IP))
    {
        return;
    }

    /** Network, Ip: packet = frame data = packet header + packet data
     * this packet != packet variable, packet variable is frame*/
    // viewdone: why frame_hdr+1? -> ptr+1 means ptr+sizeof(type being pointed), so here +1 means +sizeof(frame_hdr)
    // viewtodo: reinterpret_cast vs static_cast vs dynamic_cast vs const_cast
    const iphdr *pkt_hdr = reinterpret_cast<const iphdr *>(frame_hdr + 1);
    if (static_cast<unsigned int>(pkt_hdr->protocol) != IPPROTO_UDP)
        return;

    /** transport, MoldUDP64 message=downstreampacket:
     * downstreampacket = packet data = downstreampacket header + downstreampacket data
     * message != message block, message block is in ITCH, message (downstream packet) is in MoldUDP64*/
    const Midas::XSES::ITCH::DownstreampacketHeader *dspkt_hdr =
        reinterpret_cast<const Midas::XSES::ITCH::DownstreampacketHeader *>(packet + UDP_HEADER_LENGTH);
    const Alpha_t<SESSION_LENGTH> session = dspkt_hdr->get_session();
    const uint64_t seqNum = dspkt_hdr->get_sequence_number();
    const uint16_t msgCnt = dspkt_hdr->get_message_count();
    std::size_t offset = UDP_HEADER_LENGTH + DOWNSTREAMPACKET_HEADER_LENGTH;

    // std::cout << "check finished" << std::endl;

    /**application, ITCH:
     * message blocks = downstreampacket data = (message len + message data) * msgCnt
     * downstreampacket
     * */
    if (msgCnt == 0)
    {
        std::cout<<"heartbeat, next expected sequence number: "<<seqNum<<std::endl;
        // printf("heartbeat, next expected sequence number: %016x\n", seqNum);
        return;
    }
    if (msgCnt == 0xFFFF)
    {
        /**
         * While the End of Session messages persist,
         * re-requests may be made on the current session.
         * This is the last chance to ensure that all messages have been received
         */
        std::cout<<"end of session, next expected sequence number: "<<seqNum<<std::endl;
        // printf("end of session, next expected sequence number: %016x\n", seqNum);
        return;
    }
    // std::cout << "msg cnt " << msgCnt << std::endl;
    for (auto msgIdx = 0; msgIdx < msgCnt; ++msgIdx)
    {
        const Midas::XSES::ITCH::MessageBlock *msgBlk =
            reinterpret_cast<const Midas::XSES::ITCH::MessageBlock *>(packet + offset);
        const Midas::XSES::ITCH::MessageInfo *msgInfo =
            reinterpret_cast<const Midas::XSES::ITCH::MessageInfo *>(msgBlk->messageData);

        // printf("seqNum: %016x, msgLen: %d, msgType: %x\n",
        //     seqNum + msgIdx, msgBlk->get_message_len(), *msgBlk->messageData);
        std::cout 
                << alpha_to_string(session) << ","
                << seqNum + msgIdx << ","
                << decode(msgInfo) 
                << std::endl;
        offset += msgBlk->get_size();
    }
}

int main(int argc, char const *argv[])
{
    const char *pcap_loc = "/tmp/to_ywu/20240125.pcap";
    char error_buf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_offline(pcap_loc, error_buf);
    if (!pcap)
    {
        std::cout << error_buf << std::endl;
        return 1;
    }

    u_char *additional_args = NULL;
    pcap_loop(pcap, 20, callback, additional_args);

    return 0;
}
