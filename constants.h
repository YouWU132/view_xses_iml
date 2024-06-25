#pragma once

#include <iostream>
#include <array>

namespace Midas::XSES::ITCH
{

    /**
     * ITCH data types
     */
    using Numeric1_t = uint8_t;
    using Numeric2_t = uint16_t;
    using Numeric4_t = uint32_t;
    using Numeric8_t = uint64_t;
    using Numeric16_t = __uint128_t;

    // add padding to tail
    template <std::size_t Size, typename = std::enable_if_t<(Size > 1)>>
    using Alpha_t = std::array<char, Size>;

    using Price_t = int32_t;

    using Date_t = uint32_t;

    // Alpha<1> is char

    /**
     * ETH, IP constants
     */
    #define UDP_HEADER_LENGTH 42

    /**
     * MoldUDP64 constants
     */
    #define SESSION_LENGTH 10
    #define SEQUENCE_NUMBER_LENGTH 8
    #define MESSAGE_COUNT_LENGTH 2
    #define DOWNSTREAMPACKET_HEADER_LENGTH SESSION_LENGTH+SEQUENCE_NUMBER_LENGTH+MESSAGE_COUNT_LENGTH

    /**
     * ITCH constants
     */
    #define MAX_LEN_PER_MESSAGE 1024
    enum class MessageType : uint8_t
    {
        AddOrder = 'A',
        OrderExecutedWithPrice = 'C',
        OrderDelete = 'D',
        OrderExecuted = 'E',
        EndOfSnapshot = 'G',
        TickSize = 'L',
        CombinationOrderBookDirectory = 'M',
        OrderBookState = 'O',
        TradeMessageIdentifier = 'P',
        OrderBookDirectory = 'R',
        SystemEvent = 'S',
        Seconds = 'T',
        OrderReplace = 'U',
        EquilibriumPriceUpdate = 'Z'
    };
    enum class FinancialProduct : Numeric1_t
    {
        Option = 1,
        Forward = 2,
        Future = 3,
        FRA = 4,
        Cash = 5,
        Payment = 6,
        ExchangeRate = 7,
        InterestRateSwap = 8,
        REPO = 9,
        SyntheticBoxLegReference = 10,
        StandardCombination = 11,
        Guarantee = 12,
        OTCGeneral = 13,
        EquityWarrant = 14,
        SecurityLending = 15
    };
    enum class OptionType : Numeric1_t
    {
        Undefined = 0,
        Call = 1,
        Put = 2
    };
    

} // namespace Midas::XSES::ITCH
