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
#include <pow/dgw.h>
#include <pow/digishield.h>
#include <pow/kgw.h>
#include <pow/lwma.h>
#include <pow/peercoin.h>
#include <pow/pid1238.h>
#include <uint256.h>
#include "chainparams.h"

unsigned int GetNextWorkRequired_CIP01(const CBlockIndex* pindexLast, const CBlockHeader* pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);
    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();

    // Only change once per difficulty adjustment interval
    if ((pindexLast->nHeight + 1) % params.DifficultyAdjustmentIntervalV1() != 0) {
        if (params.fPowAllowMinDifficultyBlocks) {
            // Special difficulty rule for testnet:
            // If the new block's timestamp is more than 2* 10 minutes
            // then allow mining of a min-difficulty block.
            if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing * 2)
                return nProofOfWorkLimit;
            else {
                // Return the last non-special-min-difficulty-rules-block
                const CBlockIndex* pindex = pindexLast;
                while (pindex->pprev && pindex->nHeight % params.DifficultyAdjustmentIntervalV1() != 0 && pindex->nBits == nProofOfWorkLimit)
                    pindex = pindex->pprev;
                return pindex->nBits;
            }
        }
        return pindexLast->nBits;
    }

    // Go back by what we want to be 14 days worth of blocks
    // Litecoin: This fixes an issue where a 51% attack can change difficulty at will.
    // Go back the full period unless it's the first retarget after genesis. Code courtesy of Art Forz
    int blockstogoback = params.DifficultyAdjustmentIntervalV1() - 1;
    if ((pindexLast->nHeight + 1) != params.DifficultyAdjustmentIntervalV1())
        blockstogoback = params.DifficultyAdjustmentIntervalV1();

    // Go back by what we want to be 14 days worth of blocks
    const CBlockIndex* pindexFirst = pindexLast;
    for (int i = 0; pindexFirst && i < blockstogoback; i++)
        pindexFirst = pindexFirst->pprev;

    assert(pindexFirst);

    if (params.fPowNoRetargeting)
        return pindexLast->nBits;

    // Limit adjustment step
    int64_t nActualTimespan = pindexLast->GetBlockTime() - pindexFirst->GetBlockTime();
    if (nActualTimespan < params.nPowTargetTimespanV1 / 4)
        nActualTimespan = params.nPowTargetTimespanV1 / 4;
    if (nActualTimespan > params.nPowTargetTimespanV1 * 4)
        nActualTimespan = params.nPowTargetTimespanV1 * 4;

    // Retarget
    arith_uint256 bnNew;
    arith_uint256 bnOld;
    bnNew.SetCompact(pindexLast->nBits);
    bnOld = bnNew;
    // Litecoin: intermediate uint256 can overflow by 1 bit
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    bool fShift = bnNew.bits() > bnPowLimit.bits() - 1;
    if (fShift)
        bnNew >>= 1;
    bnNew *= nActualTimespan;
    bnNew /= params.nPowTargetTimespanV1;
    if (fShift)
        bnNew <<= 1;

    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;

    return bnNew.GetCompact();
}

unsigned int GetNextWorkRequired_CIP02(const CBlockIndex* pindexLast, const CBlockHeader* pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);
    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();

    // Only change once per difficulty adjustment interval
    if ((pindexLast->nHeight + 1) % params.DifficultyAdjustmentIntervalV2() != 0) {
        if (params.fPowAllowMinDifficultyBlocks) {
            // Special difficulty rule for testnet:
            // If the new block's timestamp is more than 2* 10 minutes
            // then allow mining of a min-difficulty block.
            if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing * 2)
                return nProofOfWorkLimit;
            else {
                // Return the last non-special-min-difficulty-rules-block
                const CBlockIndex* pindex = pindexLast;
                while (pindex->pprev && pindex->nHeight % params.DifficultyAdjustmentIntervalV2() != 0 && pindex->nBits == nProofOfWorkLimit)
                    pindex = pindex->pprev;
                return pindex->nBits;
            }
        }
        return pindexLast->nBits;
    }

    // Go back by what we want to be 14 days worth of blocks
    // Litecoin: This fixes an issue where a 51% attack can change difficulty at will.
    // Go back the full period unless it's the first retarget after genesis. Code courtesy of Art Forz
    int blockstogoback = params.DifficultyAdjustmentIntervalV2() - 1;
    if ((pindexLast->nHeight + 1) != params.DifficultyAdjustmentIntervalV2())
        blockstogoback = params.DifficultyAdjustmentIntervalV2();

    // Go back by what we want to be 14 days worth of blocks
    const CBlockIndex* pindexFirst = pindexLast;
    for (int i = 0; pindexFirst && i < blockstogoback; i++)
        pindexFirst = pindexFirst->pprev;

    assert(pindexFirst);

    if (params.fPowNoRetargeting)
        return pindexLast->nBits;

    // Limit adjustment step
    int64_t nActualTimespan = pindexLast->GetBlockTime() - pindexFirst->GetBlockTime();
    if (nActualTimespan < params.nPowTargetTimespanV2 / 4)
        nActualTimespan = params.nPowTargetTimespanV2 / 4;
    if (nActualTimespan > params.nPowTargetTimespanV2 * 4)
        nActualTimespan = params.nPowTargetTimespanV2 * 4;

    // Retarget
    arith_uint256 bnNew;
    arith_uint256 bnOld;
    bnNew.SetCompact(pindexLast->nBits);
    bnOld = bnNew;
    // Litecoin: intermediate uint256 can overflow by 1 bit
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    bool fShift = bnNew.bits() > bnPowLimit.bits() - 1;
    if (fShift)
        bnNew >>= 1;
    bnNew *= nActualTimespan;
    bnNew /= params.nPowTargetTimespanV2;
    if (fShift)
        bnNew <<= 1;

    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;

    return bnNew.GetCompact();
}

unsigned int GetNextWorkRequired_CIP03(const CBlockIndex* pindexLast, const CBlockHeader* pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);

    // Catcoin: This fixes an issue where a 51% attack can change difficulty at will.
    // Go back the full period unless it's the first retarget after genesis. Code courtesy of Art Forz
    int blockstogoback = params.DifficultyAdjustmentIntervalV2();
    if ((pindexLast->nHeight + 1) != params.DifficultyAdjustmentIntervalV2())
        blockstogoback = params.DifficultyAdjustmentIntervalV2();

    // Go back by what we want to be 14 days worth of blocks
    const CBlockIndex* pindexFirst = pindexLast;
    for (int i = 0; pindexFirst && i < blockstogoback; i++)
        pindexFirst = pindexFirst->pprev;

    assert(pindexFirst);

    if (params.fPowNoRetargeting)
        return pindexLast->nBits;

    // Limit adjustment step
    int numerator = 112;
    int denominator = 100;
    int64_t nActualTimespan = pindexLast->GetBlockTime() - pindexFirst->GetBlockTime();
    int64_t lowLimit = params.nPowTargetTimespanV2 * denominator / numerator;
    int64_t highLimit = params.nPowTargetTimespanV2 * numerator / denominator;
    if (nActualTimespan < lowLimit)
        nActualTimespan = lowLimit;
    if (nActualTimespan > highLimit)
        nActualTimespan = highLimit;

    // Retarget
    arith_uint256 bnNew;
    arith_uint256 bnOld;
    bnNew.SetCompact(pindexLast->nBits);
    bnOld = bnNew;
    // Litecoin: intermediate uint256 can overflow by 1 bit
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    bool fShift = bnNew.bits() > bnPowLimit.bits() - 1;
    if (fShift)
        bnNew >>= 1;
    bnNew *= nActualTimespan;
    bnNew /= params.nPowTargetTimespanV2;
    if (fShift)
        bnNew <<= 1;

    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;

    return bnNew.GetCompact();
}

unsigned int GetNextWorkRequired_CIP04(const CBlockIndex* pindexLast, const CBlockHeader* pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);

    int64_t nActualTimespan;
    CBigNum bnNew;
    const CBlockIndex* pindexFirst = pindexLast;

    int64_t error;
    double pGainUp = -0.005125; // Theses values can be changed to tune the PID formula
    double iGainUp = -0.0225;   // Theses values can be changed to tune the PID formula
    double dGainUp = -0.0075;   // Theses values can be changed to tune the PID formula

    double pGainDn = -0.005125; // Theses values can be changed to tune the PID formula
    double iGainDn = -0.0525;   // Theses values can be changed to tune the PID formula
    double dGainDn = -0.0075;   // Theses values can be changed to tune the PID formula

    double pCalc;
    double iCalc;
    double dCalc;
    double dResult;
    int64_t result;
    CBigNum bResult;

    pindexFirst = pindexLast->pprev;
    for (int i = 0; i < 7; i++)
        pindexFirst = pindexFirst->pprev;
    nActualTimespan = pindexLast->GetBlockTime() - pindexFirst->GetBlockTime();
    nActualTimespan = nActualTimespan / 8;

    bnNew.SetCompact(pindexLast->nBits);
    int i = 0;
    while (bnNew > 0)
    {
        i++;
        bnNew = bnNew >> 1;
        if (i > 256)
            bnNew = 0;
    }
    bnNew.SetCompact(pindexLast->nBits);


    error = nActualTimespan - params.nPowTargetSpacing;
    if (error >= -450 && error <= 450)
    {
        pCalc = pGainUp * (double)error;
        iCalc = iGainUp * (double)error * (double)((double)params.nPowTargetSpacing / (double)nActualTimespan);
        dCalc = dGainUp * ((double)error / (double)nActualTimespan) * iCalc;
    }
    else
    {
        pCalc = pGainDn * (double)error;
        iCalc = iGainDn * (double)error * (double)((double)params.nPowTargetSpacing / (double)nActualTimespan);
        dCalc = dGainDn * ((double)error / (double)nActualTimespan) * iCalc;
    }

    if (error > -10 && error < 10) {
        return bnNew.GetCompact();
    }

    dResult = pCalc + iCalc + dCalc;

    result = (int64_t)(dResult * 65536);
    while (result > 8388607)
        result = result / 2;
    bResult = result; 
    if (i > 24)
        bResult = bResult << (i - 24);
    bnNew = bnNew - bResult;

    if (bnNew.GetCompact() > 0x1e0fffff)
        bnNew.SetCompact(0x1e0fffff);

    return bnNew.GetCompact();
}

unsigned int GetNextWorkRequired_CIP05(const CBlockIndex* pindexLast, const CBlockHeader* pblock, const Consensus::Params& params)
{
    static CBigNum bnProofOfWorkLimit(params.powLimit);

    int64_t timestamp = (pindexLast->GetBlockTime() % 60); // Get the seconds portion of the last block
    if ((timestamp >= 0 && timestamp <= 14) || (timestamp >= 30 && timestamp <= 44)) {
        const CBlockIndex* pindexPrev = pindexLast->pprev;
        assert(pindexPrev);
        int64_t nActualTimespan = pindexLast->GetBlockTime() - pindexPrev->GetBlockTime();

        // limit difficulty changes between 50% and 125% (human view)
        if (nActualTimespan < (params.nPowTargetSpacing - (params.nPowTargetSpacing/4)) ) nActualTimespan = (params.nPowTargetSpacing - (params.nPowTargetSpacing/4));
        if (nActualTimespan > (params.nPowTargetSpacing + (params.nPowTargetSpacing/2)) ) nActualTimespan = (params.nPowTargetSpacing + (params.nPowTargetSpacing/2));

        // calculate new difficulty
        CBigNum bnNew;
        bnNew.SetCompact(pindexLast->nBits);
        bnNew *= nActualTimespan;
        bnNew /= params.nPowTargetSpacing;

        // difficulty should never go below (human view) the starting difficulty
        if (bnNew > bnProofOfWorkLimit) {
            bnNew = bnProofOfWorkLimit;
        }

	    // Make sure that diff is not set too low, ever ... Might find a min diff higher than 0.000228882 (or 15 on cgminer's output)
	    if (bnNew.GetCompact() > 0x1e0fffff) {
            bnNew.SetCompact(0x1e0fffff);
        }
        return bnNew.GetCompact();
    }

    return GetNextWorkRequired_CIP04(pindexLast, pblock, params);
}

unsigned int GetNextWorkRequired_CIP06(const CBlockIndex* pindexLast, const CBlockHeader* pblock, const Consensus::Params& params)
{
    int64_t timestamp = (pindexLast->GetBlockTime() % 60); // Get the seconds portion of the last block
    if ((timestamp >= 0 && timestamp <= 14) || (timestamp >= 30 && timestamp <= 44)) {
        return GetNextWorkRequired_DigiShield(pindexLast, pblock, params);
    }
    return GetNextWorkRequired_PID1238(pindexLast, pblock, params);
}

unsigned int GetNextWorkRequired_CIP07(const CBlockIndex* pindexLast, const CBlockHeader* pblock, const Consensus::Params& params)
{
    return GetNextWorkRequired_PID1238(pindexLast, pblock, params);
}

unsigned int GetNextWorkRequired_CIP08(const CBlockIndex* pindexLast, const CBlockHeader* pblock, const Consensus::Params& params)
{
    return GetNextWorkRequired_DGW(pindexLast, pblock, params);
}

unsigned int GetNextWorkRequired_CIP09(const CBlockIndex* pindexLast, const CBlockHeader* pblock, const Consensus::Params& params)
{
    auto pid1238 = GetNextWorkRequired_PID1238(pindexLast, pblock, params);
    auto digishield = GetNextWorkRequired_DigiShield(pindexLast, pblock, params);
    auto lwma = GetNextWorkRequired_LWMA(pindexLast, pblock, params);
    auto dgw = GetNextWorkRequired_DGW(pindexLast, pblock, params);
    auto peercoin = GetNextWorkRequired_Peercoin(pindexLast, pblock, params);

    // Add Results to list and sort top to bottom and bin the top 2
    std::list<unsigned int> results = {pid1238, digishield, lwma, dgw, peercoin};
    results.sort();

    // Remove front and back
    results.pop_front();
    results.pop_back();

    auto total = accumulate(results.begin(), results.end(), (unsigned int) 0.0);
    return total / results.size();
}

unsigned int GetNextWorkRequired_CIP10(const CBlockIndex* pindexLast, const CBlockHeader* pblock, const Consensus::Params& params)
{
    auto pid1238 = GetNextWorkRequired_PID1238(pindexLast, pblock, params);
    auto kgw = GetNextWorkRequired_KGW(pindexLast, pblock, params);
    auto lwma = GetNextWorkRequired_LWMA(pindexLast, pblock, params);
    auto dgw = GetNextWorkRequired_DGW(pindexLast, pblock, params);
    auto peercoin = GetNextWorkRequired_Peercoin(pindexLast, pblock, params);

    // Add Results to list and sort top to bottom and bin the top 2
    std::list<unsigned int> results = {pid1238, kgw, lwma, dgw, peercoin};
    results.sort();

    // Remove front and back
    results.pop_front();
    results.pop_back();

    auto total = accumulate(results.begin(), results.end(), (unsigned int) 0.0);
    return total / results.size();
}

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader* pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);
    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();

    // Genesis block
    if (pindexLast == NULL)
        return nProofOfWorkLimit;

    if (params.fPowAllowMinDifficultyBlocks)
    {
        // Special difficulty rule for testnet:
        // If the new block's timestamp is more than 2* 10 minutes
        // then allow mining of a min-difficulty block.
        if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing*2)
            return nProofOfWorkLimit;
        else
        {
            // Return the last non-special-min-difficulty-rules-block
            const CBlockIndex* pindex = pindexLast;
            while (pindex->pprev && pindex->nHeight % params.DifficultyAdjustmentIntervalV2() != 0 && pindex->nBits == nProofOfWorkLimit)
                pindex = pindex->pprev;
            return pindex->nBits;
        }
    }
    
    if (params.fPowNoRetargeting)
        return pindexLast->nBits;

    if (pindexLast->nHeight < params.CIP01Height)
        return GetNextWorkRequired_CIP01(pindexLast, pblock, params);

    if (pindexLast->nHeight == params.CIP01Height) {
        CBigNum bnNew;
        bnNew.SetCompact(0x1c0ffff0); // Difficulty 16
        return bnNew.GetCompact();
    }

    if (pindexLast->nHeight < params.CIP02Height)
        return GetNextWorkRequired_CIP02(pindexLast, pblock, params);

    if (pindexLast->nHeight < params.CIP03Height)
        return GetNextWorkRequired_CIP03(pindexLast, pblock, params);

    if (pindexLast->nHeight < params.CIP04Height)
        return GetNextWorkRequired_CIP04(pindexLast, pblock, params);

    auto network = Params().NetworkIDString();
    if (network == CBaseChainParams::TESTNET1) {
        return GetNextWorkRequired_CIP06(pindexLast, pblock, params);
    } else if (network == CBaseChainParams::TESTNET2) {
        return GetNextWorkRequired_CIP07(pindexLast, pblock, params);
    } else if (network == CBaseChainParams::TESTNET3) {
        return GetNextWorkRequired_CIP08(pindexLast, pblock, params);
    } else if (network == CBaseChainParams::TESTNET4) {
        return GetNextWorkRequired_CIP09(pindexLast, pblock, params);
    } else if (network == CBaseChainParams::TESTNET5) {
        return GetNextWorkRequired_CIP10(pindexLast, pblock, params);
    }
    return GetNextWorkRequired_CIP05(pindexLast, pblock, params);
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit))
        return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}
