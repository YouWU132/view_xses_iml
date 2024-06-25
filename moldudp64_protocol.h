
#pragma once
#include <pcap.h>
#include <iostream>
#include <cstdint>
#include <array>

#include "utils.h"

/** transport layer, deal with packets
 * packet = packet header + message
 */

namespace Midas::XSES::ITCH
{

#pragma pack(push, 1)

struct MoldUDP64Header
{
	Alpha_t<SESSION_LENGTH> session;
	uint64_t sequenceNumber;
	uint16_t messageCount;
	Alpha_t<SESSION_LENGTH> get_session() const noexcept
	{
		return session;
	}
	std::size_t get_sequence_number() const noexcept
	{
		return big_endian_to_host(sequenceNumber);
	}
	std::size_t get_message_count() const noexcept
	{
		return big_endian_to_host(messageCount);
	}
	static constexpr std::size_t get_size() noexcept
	{
		return sizeof(MoldUDP64Header);
	}
};
static_assert(MoldUDP64Header::get_size() == DOWNSTREAMPACKET_HEADER_LENGTH);

#pragma pack(pop)
} // namespace Midas::XSES::ITCH
