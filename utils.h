#pragma once
#include <cstdint>
#include <endian.h>
#include <string>

#include "constants.h"

namespace Midas::XSES::ITCH
{

template <typename TInteger>
constexpr TInteger big_endian_to_host(TInteger integer)
{
    /* host to big endian, host (intel) is little endian */
    /* F is 4 bit, 0F is a byte (8 bit), 32-bit is 0x00 00 0F 00*/
    /* 0x00 0F -> 0x0F 00 */
    if (sizeof(TInteger)==sizeof(uint16_t)) return be16toh(integer);
    /* 0x00 00 0F 00 -> 0x00 0F 00 00 */
    if (sizeof(TInteger)==sizeof(uint32_t)) return be32toh(integer);
    if (sizeof(TInteger)==sizeof(uint64_t)) return be64toh(integer);
    return integer;
}


template <typename TInteger>
constexpr TInteger host_to_big_endian(TInteger integer)
{
    // host to big endian, host (intel) is little endian
    if (sizeof(TInteger)==sizeof(uint16_t)) return htobe16(integer);
    if (sizeof(TInteger)==sizeof(uint32_t)) return htobe32(integer);
    if (sizeof(TInteger)==sizeof(uint64_t)) return htobe64(integer);
    return integer;
}

template <std::size_t Size>
std::string alpha_to_string(const Alpha_t<Size>& s)
{
    for (int i = Size; i > 0; --i)
    {
        // remove padding?
        // padded with ' ' from right to left
        // viewtodo: how do we know padded with empty space?
        if (s[i - 1] != ' ') return std::string(s.data(), i);
    }
    return std::string();
}

}  //namespace Midas::XSES::ITCH
