#pragma once

#include <pcap.h>
#include <iostream>
#include <cstdint>

#include "utils.h"
#include "moldudp64_protocol.h"

#pragma pack(push,1)

/** transport layer, deal with messages
 * message = message header + message data
 */

namespace Midas::XSES::ITCH
{
    struct MessageBlock
    {
        private:
            uint16_t messageLen;
        public:
            u_char messageData[0];
            std::size_t get_message_len() const noexcept
            {
                return big_endian_to_host(messageLen);
            }
            u_char const * get_message_data() const noexcept
            {
                return messageData;
            }
            constexpr std::size_t get_size() const noexcept
            {
                // viewtodo:  error: the value of ‘Midas::XSES::ITCH::MessageBlock::messageLen’ is not usable in a constant expression
                return sizeof(MessageBlock) + big_endian_to_host(messageLen);
            }
    };

    struct MessageInfo
    {
        MessageType messageType;
        MessageType get_message_type() const noexcept
        {
            return messageType;
        }
        static constexpr std::size_t get_size() noexcept
        {
            return sizeof(MessageInfo);
        }
    };

    /**
     * 3.3.2 Message Formats
     */
    struct Seconds: MessageInfo
    {
        Numeric4_t second;
        std::string to_string() const
        {
            char buffer[1024];
            std::sprintf(buffer, "%c,%u",
                static_cast<char>(messageType),
                big_endian_to_host(second));
            return buffer;
        }
    };

    /**
     * 3.3.3 Reference Data Messages
     */
    struct OrderBookDirectory: MessageInfo
    {
        Numeric4_t mTimestampNanoseconds;  // Nanoseconds portion of the timestamp
        /**
         * Denotes the primary identifier of an Order Book
         * @note Expired Order Book ID’s may be reused for new instruments
        */
        Numeric4_t mOrderBookId;
        Alpha_t<32> mSymbol;  // Instrument short name
        Alpha_t<32> mLongName;  // Human readable long name of Instrument series
        Alpha_t<12> mIsin;  // ISIN code identifying security
        FinancialProduct mFinancialProduct;
        Alpha_t<3> mTradingCurrency;
        /**
         * This value defines the number of decimals used in price for this Order Book
         * @note A value of 256 means that the instrument is traded in fractions 
         * (each fraction is 1/256)
        */
        Numeric2_t mNumberOfDecimalsInPrice;
        Numeric2_t mNumberOfDecimalsInNominalValue;  // This value defines the number of decimals in Nominal Value
        Numeric4_t mOddLotSize;
        Numeric4_t mRoundLotSize;
        Numeric4_t mBlockLotSize;
        Numeric8_t mNominalValue;
        Numeric1_t mNumberOfLegs;
        Numeric4_t mCommodityCode;
        Price_t mStrikePrice;
        Date_t mExpirationDate;
        Numeric2_t mNumberOfDecimalsInStrikePrice;
        OptionType mPutOrCall;

        static constexpr std::size_t Size() noexcept
        {
            return sizeof(OrderBookDirectory);
        }

        std::string to_string() const
        {
            char buffer[1024];
            std::sprintf(buffer, "%c,%u,%u,%s,%s,%s,%u,%s,%u,%u,%u,%u,%u,%lu,%u,%u,%d,%u,%u,%u",
                static_cast<char>(messageType),
                big_endian_to_host(mTimestampNanoseconds),
                big_endian_to_host(mOrderBookId),
                alpha_to_string(mSymbol).c_str(),
                alpha_to_string(mLongName).c_str(),
                alpha_to_string(mIsin).c_str(),
                mFinancialProduct,
                alpha_to_string(mTradingCurrency).c_str(),
                big_endian_to_host(mNumberOfDecimalsInPrice),
                big_endian_to_host(mNumberOfDecimalsInNominalValue),
                big_endian_to_host(mOddLotSize),
                big_endian_to_host(mRoundLotSize),
                big_endian_to_host(mBlockLotSize),
                big_endian_to_host(mNominalValue),
                big_endian_to_host(mNumberOfLegs),
                big_endian_to_host(mCommodityCode),
                big_endian_to_host(mStrikePrice),
                big_endian_to_host(mExpirationDate),
                big_endian_to_host(mNumberOfDecimalsInStrikePrice),
                mPutOrCall
            );
            return buffer;
        }
    };
    
    struct CombinationOrderBookLeg: MessageInfo
    {
        Numeric4_t mTimestampNanoseconds;
        Numeric4_t mCombinationOrderBookId;
        Numeric4_t mLegOrderBookId;
        /**
         * Specifies whether to buy or sell the Leg Series when buying or selling the combination.
         * - 'B' = As Defined
         * - 'C' = Opposite
        */
        char mLegSide;
        Numeric4_t mLegRatio;

        static constexpr std::size_t Size() noexcept
        {
            return sizeof(CombinationOrderBookLeg);
        }

        std::string to_string() const
        {
            char buffer[1024];
            std::sprintf(buffer, "%c,%u,%u,%u,%c,%u",
                static_cast<char>(messageType),
                big_endian_to_host(mTimestampNanoseconds),
                big_endian_to_host(mCombinationOrderBookId),
                big_endian_to_host(mLegOrderBookId),
                mLegSide,
                big_endian_to_host(mLegRatio)
            );
            return buffer;
        }
    };

    struct TickSizeTableEntry: MessageInfo
    {
        Numeric4_t mTimestampNanoseconds;
        Numeric4_t mOrderBookId;
        Numeric8_t mTickSize;  // Tick Size for the given price range
        Price_t mPriceFrom;  // Start of price range for this entry
        Price_t mPriceTo;  // End of price range for this entry, zero (0) means infinity

        static constexpr std::size_t Size() noexcept
        {
            return sizeof(TickSizeTableEntry);
        }

        std::string to_string() const
        {
            char buffer[1024];
            std::sprintf(buffer, "%c,%u,%u,%lu,%d,%d",
                static_cast<char>(messageType),
                big_endian_to_host(mTimestampNanoseconds),
                big_endian_to_host(mOrderBookId),
                big_endian_to_host(mTickSize),
                big_endian_to_host(mPriceFrom),
                big_endian_to_host(mPriceTo)
            );
            return buffer;
        }
    };

    /**
     * 3.3.4. Event & State Change Message
     */
    struct SystemEvent: MessageInfo
    {
        Numeric4_t mTimestampNanoseconds;
        /**
         * - 'O': Start Of Messages
         * Outside of time stamp messages, the start of day message is the first message sent 
         * in any trading day
         * - 'C': End of Messages
         * This is always the last message sent in any trading day
        */
        char mEventCode;

        static constexpr std::size_t Size() noexcept
        {
            return sizeof(SystemEvent);
        }

        std::string to_string() const
        {
            char buffer[1024];
            std::sprintf(buffer, "%c,%u,%c",
                static_cast<char>(messageType),
                big_endian_to_host(mTimestampNanoseconds),
                mEventCode
            );
            return buffer;
        }
    };

    struct OrderBookState: MessageInfo
    {
        Numeric4_t mTimestampNanoseconds;
        Numeric4_t mOrderBookId;
        Alpha_t<20> mStateName;

        static constexpr std::size_t Size() noexcept
        {
            return sizeof(OrderBookState);
        }

        std::string to_string() const
        {
            char buffer[1024];
            std::sprintf(buffer, "%c,%u,%u,%s",
                static_cast<char>(messageType),
                big_endian_to_host(mTimestampNanoseconds),
                big_endian_to_host(mOrderBookId),
                alpha_to_string(mStateName).c_str()
            );
            return buffer;
        }
    };

    /**
     * 3.3.5. Market by Order Message
     */
    struct AddOrder: MessageInfo
    {
        Numeric4_t mTimestampNanoseconds;
        Numeric8_t mOrderId;  // The identifier assigned to the new order Note that the number is only unique per Order Book and side
        Numeric4_t mOrderBookId;
        /**
         * The type of order being added:
         * - 'B' = Buy order
         * - 'S' = Sell order
        */
        char mSide;
        Numeric4_t mOrderBookPosition;  // Rank within the Order Book
        /**
         * The visible quantity of the order
         * @note Orders with an undisclosed quantity will have this field set to 0
        */
        Numeric8_t mQuantity;
        Price_t mPrice;
        /**
         * Additional order attributes Values:
         * - 0 = Not applicable
         * - 8192 = Bait/implied order
        */
        Numeric2_t mOrderAttributes;
        Numeric1_t mLotType;

        static constexpr std::size_t Size() noexcept
        {
            return sizeof(AddOrder);
        }

        std::string to_string() const
        {
            char buffer[1024];
            std::sprintf(buffer, "%c,%u,%016lX,%u,%c,%u,%lu,%d,%u,%u",
                static_cast<char>(messageType),
                big_endian_to_host(mTimestampNanoseconds),
                big_endian_to_host(mOrderId),
                big_endian_to_host(mOrderBookId),
                mSide,
                big_endian_to_host(mOrderBookPosition),
                big_endian_to_host(mQuantity),
                big_endian_to_host(mPrice),
                big_endian_to_host(mOrderAttributes),
                big_endian_to_host(mLotType)
            );
            return buffer;
        }
    };
    
    struct OrderExecuted: MessageInfo
    {
        Numeric4_t mTimestampNanoseconds;
        Numeric8_t mOrderId;
        Numeric4_t mOrderBookId;
        char mSide;
        Numeric8_t mExecutedQuantity;
        Numeric8_t mMatchId;
        Numeric4_t mComboGroupId;
        Alpha_t<7> mReserved1;
        Alpha_t<7> mReserved2;

        static constexpr std::size_t Size() noexcept
        {
            return sizeof(OrderExecuted);
        }

        std::string to_string() const
        {
            char buffer[1024];
            std::sprintf(buffer, "%c,%u,%016lX,%u,%c,%lu,%016lX,%u",
                static_cast<char>(messageType),
                big_endian_to_host(mTimestampNanoseconds),
                big_endian_to_host(mOrderId),
                big_endian_to_host(mOrderBookId),
                mSide,
                big_endian_to_host(mExecutedQuantity),
                big_endian_to_host(mMatchId),
                big_endian_to_host(mComboGroupId)
            );
            return buffer;
        }
    };

    struct OrderExecutedWithPrice: OrderExecuted
    {
        Price_t mTradePrice;
        /**
         * Values:
         * - 'Y' = Yes, trade occurred at the cross
         * - 'N' = No, trade occurred at continuous market
        */
        char mOccurredAtCross;
        /**
         * Indicates if the trade should be included in trade tickers and volume calculations
         * Values:
         * - 'Y' = Printable 
         * - 'N' = Non-printable
        */
        char mPrintable;

        static constexpr std::size_t Size() noexcept
        {
            return sizeof(OrderExecutedWithPrice);
        }

        std::string to_string() const
        {
            char buffer[1024];
            std::sprintf(buffer, "%s,%d,%c,%c",
                OrderExecuted::to_string().c_str(),
                big_endian_to_host(mTradePrice),
                mOccurredAtCross,
                mPrintable
            );
            return buffer;
        }
    };

    struct OrderReplace: MessageInfo
    {
        Numeric4_t mTimestampNanoseconds;
        Numeric8_t mOrderId;
        Numeric4_t mOrderBookId;
        char mSide;
        Numeric4_t mNewOrderBookPosition;
        Numeric8_t mQuantity;
        Price_t mPrice;
        Numeric2_t mOrderAttributes;

        static constexpr std::size_t Size() noexcept
        {
            return sizeof(OrderReplace);
        }

        std::string to_string() const
        {
            return "unused message type";
        }
    };

    struct OrderDelete: MessageInfo
    {
        // MessageType MessageInfo::messageType;
        Numeric4_t timestampNanoseconds;
        Numeric8_t orderId;
        Numeric4_t orderBookId;
        char side;

        static constexpr std::size_t get_size() noexcept
        {
            return sizeof(OrderDelete);
        }

        std::string to_string() const
        {
            char buffer[MAX_LEN_PER_MESSAGE];
            std::sprintf(buffer, "%c,%u,%016lX,%u,%c",
                static_cast<char>(messageType),
                big_endian_to_host(timestampNanoseconds),
                big_endian_to_host(orderId),
                big_endian_to_host(orderBookId),
                side
            );
            return buffer;
        }
    };
    
    /**
     * 3.3.6. Trade Messages
     */
    struct Trade: MessageInfo
    {
        Numeric4_t mTimestampNanoseconds;
        Numeric8_t mMatchId;
        Numeric4_t mComboGroupId;
        /**
         * The type of non-display on the book being matched
         * - 'B' = Buy order
         * - 'S' = Sell order
         * @note: Will be set to blank (space) for anonymous markets
        */
        char mSide;
        Numeric8_t mQuantity;
        Numeric4_t mOrderBookId;
        Price_t mTradePrice;
        Alpha_t<7> mReserved1;
        Alpha_t<7> mReserved2;
        char mPrintable;
        char mOccurredAtCross;

        static constexpr std::size_t Size() noexcept
        {
            return sizeof(Trade);
        }

        std::string to_string() const
        {
            char buffer[1024];
            std::sprintf(buffer, "%c,%u,%016lX,%u,%c,%lu,%u,%d,%c,%c",
                static_cast<char>(messageType),
                big_endian_to_host(mTimestampNanoseconds),
                big_endian_to_host(mMatchId),
                big_endian_to_host(mComboGroupId),
                mSide,
                big_endian_to_host(mQuantity),
                big_endian_to_host(mOrderBookId),
                big_endian_to_host(mTradePrice),
                mPrintable,
                mOccurredAtCross
            );
            return buffer;
        }
    };
    
    /**
     * 3.3.7. Auction Messages
     */
    struct EquilibriumPriceUpdate: MessageInfo
    {
        Numeric4_t mTimestampNanoseconds;
        Numeric4_t mOrderBookId;
        Numeric8_t mAvailableBidQuantityAtEquilibriumPrice;
        Numeric8_t mAvailableAskQuantityAtEquilibriumPrice;
        Price_t mEquilibriumPrice;
        Price_t mBestBidPrice;
        Price_t mBestAskPrice;
        Numeric8_t mBestBidQuantity;
        Numeric8_t mBestAskQuantity;

        static constexpr std::size_t Size() noexcept
        {
            return sizeof(EquilibriumPriceUpdate);
        }

        std::string to_string() const
        {
            char buffer[1024];
            std::sprintf(buffer, "%c,%u,%u,%lu,%lu,%d,%d,%d,%lu,%lu",
                static_cast<char>(messageType),
                big_endian_to_host(mTimestampNanoseconds),
                big_endian_to_host(mOrderBookId),
                big_endian_to_host(mAvailableBidQuantityAtEquilibriumPrice),
                big_endian_to_host(mAvailableAskQuantityAtEquilibriumPrice),
                big_endian_to_host(mEquilibriumPrice),
                big_endian_to_host(mBestBidPrice),
                big_endian_to_host(mBestAskPrice),
                big_endian_to_host(mBestBidQuantity),
                big_endian_to_host(mBestAskQuantity)
            );
            return buffer;
        }
    };


#pragma pack(pop)
} // namespace Midas::XSES::ITCH