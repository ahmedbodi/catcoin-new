// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <arith_uint256.h>
#include <bignum.h>
#include <chain.h>
#include <logging.h>
#include <primitives/block.h>
#include <uint256.h>

unsigned int KimotoGravityWell(const CBlockIndex* pindexLast,
                               const CBlockHeader* pblock,
                               uint64_t TargetBlocksSpacingSeconds,
                               uint64_t PastBlocksMin,
                               uint64_t PastBlocksMax,
                               const Consensus::Params& params)
{
    /* current difficulty formula - kimoto gravity well */
    const CBlockIndex* BlockLastSolved = pindexLast;
    const CBlockIndex* BlockReading = pindexLast;
    uint64_t PastBlocksMass = 0;
    int64_t PastRateActualSeconds = 0;
    int64_t PastRateTargetSeconds = 0;
    double PastRateAdjustmentRatio = double(1);
    CBigNum PastDifficultyAverage;
    CBigNum PastDifficultyAveragePrev;
    double EventHorizonDeviation;
    double EventHorizonDeviationFast;
    double EventHorizonDeviationSlow;
    static CBigNum bnProofOfWorkLimit(params.powLimit);

    if (BlockLastSolved == NULL || BlockLastSolved->nHeight == 0 || static_cast<uint64_t>(BlockLastSolved->nHeight) < PastBlocksMin) {
        return UintToArith256(params.powLimit).GetCompact();
    }

    for (unsigned int i = 1; BlockReading && BlockReading->nHeight > 0; i++) {
        if (PastBlocksMax > 0 && i > PastBlocksMax) {
            break;
        }
        PastBlocksMass++;

        if (i == 1) {
            PastDifficultyAverage.SetCompact(BlockReading->nBits);
        } else {
            PastDifficultyAverage = ((CBigNum().SetCompact(BlockReading->nBits) - PastDifficultyAveragePrev) / i) + PastDifficultyAveragePrev;
        }
        PastDifficultyAveragePrev = PastDifficultyAverage;

        PastRateActualSeconds = BlockLastSolved->GetBlockTime() - BlockReading->GetBlockTime();
        PastRateTargetSeconds = TargetBlocksSpacingSeconds * PastBlocksMass;
        PastRateAdjustmentRatio = double(1);
        if (PastRateActualSeconds < 0) {
            PastRateActualSeconds = 0;
        }
        if (PastRateActualSeconds != 0 && PastRateTargetSeconds != 0) {
            PastRateAdjustmentRatio = double(PastRateTargetSeconds) / double(PastRateActualSeconds);
        }
        EventHorizonDeviation = 1 + (0.7084 * std::pow((double(PastBlocksMass) / double(144)), -1.228));
        EventHorizonDeviationFast = EventHorizonDeviation;
        EventHorizonDeviationSlow = 1 / EventHorizonDeviation;

        if (PastBlocksMass >= PastBlocksMin) {
            if ((PastRateAdjustmentRatio <= EventHorizonDeviationSlow) || (PastRateAdjustmentRatio >= EventHorizonDeviationFast)) {
                assert(BlockReading);
                break;
            }
        }
        if (BlockReading->pprev == NULL) {
            assert(BlockReading);
            break;
        }
        BlockReading = BlockReading->pprev;
    }

    CBigNum bnNew(PastDifficultyAverage);
    if (PastRateActualSeconds != 0 && PastRateTargetSeconds != 0) {
        bnNew *= PastRateActualSeconds;
        bnNew /= PastRateTargetSeconds;
    }


    if (bnNew > bnProofOfWorkLimit) {
        return bnProofOfWorkLimit.GetCompact();
    }

    return bnNew.GetCompact();
}

unsigned int GetNextWorkRequired_KGW(const CBlockIndex* pindexLast, const CBlockHeader* pblock, const Consensus::Params& params)
{
    static CBigNum bnProofOfWorkLimit(params.powLimit);
    unsigned int TimeDaySeconds = 60 * 60 * 24;
    int64_t PastSecondsMin = TimeDaySeconds * 0.25;
    int64_t PastSecondsMax = TimeDaySeconds * 7;
    uint64_t PastBlocksMin = PastSecondsMin / params.nPowTargetSpacing;
    uint64_t PastBlocksMax = PastSecondsMax / params.nPowTargetSpacing;
    return KimotoGravityWell(pindexLast, pblock, params.nPowTargetSpacing, PastBlocksMin, PastBlocksMax, params);
}