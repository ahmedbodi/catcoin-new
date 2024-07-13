// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <arith_uint256.h>
#include <chain.h>
#include <primitives/block.h>
#include <uint256.h>


static const int64_t nTargetTimespan = 6 * 60 * 60; // 6 hours
static const int64_t nTargetSpacing = 10 * 60;  // 10 minute block time target
static const int64_t nInterval = nTargetTimespan / nTargetSpacing;

static const int64_t nTargetTimespanOld = 14 * 24 * 60 * 60; // two weeks
static const int64_t nIntervalOld = nTargetTimespanOld / nTargetSpacing;
static const int fork4Block = 46331;

unsigned int GetNextWorkRequired_PID(const CBlockIndex* pindexLast, const CBlockHeader* pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);

	const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    unsigned int nProofOfWorkLimit = bnPowLimit.GetCompact();
    unsigned int i;

    int64_t nTargetTimespanLocal = 0;
    int64_t nIntervalLocal = 0;
    int forkBlock = 20290 - 1;
    int fork2Block = 21346;
    int fork3Block = 27260;

    int64_t nActualTimespan;
    int64_t lowLimit;
    int64_t highLimit;
    unsigned int blockstogoback = nIntervalLocal; // was -1
    arith_uint256 bnNew;
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
    arith_uint256 bResult;
    bool fTestNet = params.fPowAllowMinDifficultyBlocks;

    if (fTestNet){
        forkBlock = -1;
	    fork2Block = 36;
    }

    // Genesis block
    if (pindexLast == NULL)
        return nProofOfWorkLimit;

    // Starting from block 20,290 the network diff was set to 16
    // and the retarget interval was changed to 36
    if (pindexLast->nHeight < forkBlock && !fTestNet) {
        nTargetTimespanLocal = nTargetTimespanOld;
        nIntervalLocal = nIntervalOld;
    } else if (pindexLast->nHeight == forkBlock && !fTestNet) {
        bnNew.SetCompact(0x1c0ffff0); // Difficulty 16
        return bnNew.GetCompact();
    } else // Keep in for a resync
    {
        nTargetTimespanLocal = nTargetTimespan;
        nIntervalLocal = nInterval;
    }

    // after fork2Block we retarget every block
    if (pindexLast->nHeight < fork2Block && !fTestNet) {
        // Only change once per interval
        if ((pindexLast->nHeight + 1) % nIntervalLocal != 0 && !fTestNet) {
            return pindexLast->nBits;
        }
    }


    if (pindexLast->nHeight < fork3Block && !fTestNet) // let it walk through 2nd fork stuff if below fork3Block, and ignore if on testnet
    {
        // Catcoin: This fixes an issue where a 51% attack can change difficulty at will.
        // Go back the full period unless it's the first retarget after genesis. Code courtesy of Art Forz
        if ((pindexLast->nHeight + 1) != nIntervalLocal)
            blockstogoback = nIntervalLocal;

        // Go back by what we want to be 14 days worth of blocks
        if (blockstogoback > 0) {
            for (i = 0; pindexFirst && i < blockstogoback; i++)
                pindexFirst = pindexFirst->pprev;
            assert(pindexFirst);
        }

        // Limit adjustment step
        int numerator = 4;
        int denominator = 1;
        if (pindexLast->nHeight >= fork2Block) {
            numerator = 112;
            denominator = 100;
        }
        nActualTimespan = pindexLast->GetBlockTime() - pindexFirst->GetBlockTime();
        lowLimit = nTargetTimespanLocal * denominator / numerator;
        highLimit = nTargetTimespanLocal * numerator / denominator;
        if (nActualTimespan < lowLimit)
            nActualTimespan = lowLimit;
        if (nActualTimespan > highLimit)
            nActualTimespan = highLimit;

        // Retarget
        bnNew.SetCompact(pindexLast->nBits);
        bnNew *= nActualTimespan;
        bnNew /= nTargetTimespanLocal;

        if (bnNew > bnPowLimit)
            bnNew = bnPowLimit;
    }


    if (pindexLast->nHeight >= fork3Block || fTestNet)
    // Fork 3 to use a PID routine instead of the other 2 forks
    {
        pindexFirst = pindexLast->pprev; // Set previous block
        for (i = 0; i < 7; i++)
            pindexFirst = pindexFirst->pprev;                                       // Set 4th previous block for 8 block filtering
        nActualTimespan = pindexLast->GetBlockTime() - pindexFirst->GetBlockTime(); // Get last X blocks time
        nActualTimespan = nActualTimespan / 8;                                      // Calculate average for last 8 blocks

        bnNew.SetCompact(pindexLast->nBits); // Get current difficulty
        i = 0;                               // Zero bit-shift counter
        while (bnNew > 0)                    // Loop while bnNew > 0
        {
            i++;                    // Increment bit-shift counter
            bnNew = bnNew >> 1;     // shift bnNew lower by 1 bit
            if (i > 256) bnNew = 0; // overflow test, just to make sure that it never stays in this loop
        }
        bnNew.SetCompact(pindexLast->nBits); // Get current difficulty again


        error = nActualTimespan - nTargetSpacing; // Calculate the error to be fed into the PID Calculation
        if (error >= -450 && error <= 450)        // Slower gains for when the average time is within 2.5 min and 7.5 min
        {
            // Calculate P ... pGainUp defined at beginning of routine
            pCalc = pGainUp * (double)error;
            // Calculate I ... iGainUp defined at beginning of routine
            iCalc = iGainUp * (double)error * (double)((double)nTargetSpacing / (double)nActualTimespan);
            // Calculate D ... dGainUp defined at beginning of routine
            dCalc = dGainUp * ((double)error / (double)nActualTimespan) * iCalc;
        } else // Faster gains for block averages faster than 2.5 min and greater than 7.5 min
        {
            // Calculate P ... pGainDn defined at beginning of routine
            pCalc = pGainDn * (double)error;
            // Calculate I ... iGainDn defined at beginning of routine
            iCalc = iGainDn * (double)error * (double)((double)nTargetSpacing / (double)nActualTimespan);
            // Calculate D ... dGainDn defined at beginning of routine
            dCalc = dGainDn * ((double)error / (double)nActualTimespan) * iCalc;
        }

        if (error > -10 && error < 10) {
            return (bnNew.GetCompact());
        }

        dResult = pCalc + iCalc + dCalc; // Sum the PID calculations

        result = (int64_t)(dResult * 65536); // Adjust for scrypt calcuation
        // Bring the result within max range to avoid overflow condition
        while (result > 8388607)
            result = result / 2;
        bResult = result;                          // Set the bignum value
        if (i > 24) bResult = bResult << (i - 24); // bit-shift integer value of result to be subtracted from current diff
        bnNew = bnNew - bResult; // Subtract the result to set the current diff

        // Make sure that diff is not set too low, ever
        if (bnNew.GetCompact() > 0x1e0fffff) bnNew.SetCompact(0x1e0fffff);

    } // End Fork 3 to use a PID routine instead of the other 2 forks routine

    return bnNew.GetCompact();
}

unsigned int GetNextWorkRequired_DIGI(const CBlockIndex* pindexLast, const CBlockHeader* pblock, const Consensus::Params& params)
{
    // Digi algorithm should never be used until at least 2 blocks are mined.
    // Contains code by RealSolid & WDC
    // Cleaned up for use in Guldencoin by GeertJohan (dead code removal since Guldencoin retargets every block)
    // retarget timespan is set to a single block spacing because there is a retarget every block
    int64_t retargetTimespan = nTargetSpacing;

    // get previous block
    const CBlockIndex* pindexPrev = pindexLast->pprev;
    assert(pindexPrev);

    // calculate actual timestpan between last block and previous block
    int64_t nActualTimespan = pindexLast->GetBlockTime() - pindexPrev->GetBlockTime();

    // limit difficulty changes between 50% and 125% (human view)
    if (nActualTimespan < (retargetTimespan - (retargetTimespan / 4))) nActualTimespan = (retargetTimespan - (retargetTimespan / 4));
    if (nActualTimespan > (retargetTimespan + (retargetTimespan / 2))) nActualTimespan = (retargetTimespan + (retargetTimespan / 2));

    // Retarget
    arith_uint256 bnNew;
    bnNew.SetCompact(pindexLast->nBits);
    // Catcoin: intermediate uint256 can overflow by 1 bit
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    bool fShift = bnNew.bits() > bnPowLimit.bits() - 1;
    if (fShift)
        bnNew >>= 1;
    bnNew *= nActualTimespan;
    bnNew /= retargetTimespan;
    if (fShift)
        bnNew <<= 1;

    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;

    return bnNew.GetCompact();
}

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader* pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);
    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();

    // Genesis block
    if (pindexLast == NULL)
        return nProofOfWorkLimit;

    if (params.fPowNoRetargeting)
        return pindexLast->nBits;

    int DiffMode = 1;
    int64_t timestamp = (pindexLast->GetBlockTime() % 60); // Get the seconds portion of the last block

    if (pindexLast->nHeight >= fork4Block || params.fPowAllowMinDifficultyBlocks) {
        if ((timestamp >= 0 && timestamp <= 14) || (timestamp >= 30 && timestamp <= 44)) {
            DiffMode = 0;
        }
    } else {
        DiffMode = 1; // Old algo
    }

    if (DiffMode == 0) {
        return GetNextWorkRequired_DIGI(pindexLast, pblock, params);
    } // DigiShield algo
    if (DiffMode == 1) {
        return GetNextWorkRequired_PID(pindexLast, pblock, params);
    } // PID Algo

    // It should never get to this next line, but force PID algo, just in case it does.
    return GetNextWorkRequired_PID(pindexLast, pblock, params);
}

unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    if (params.fPowNoRetargeting)
        return pindexLast->nBits;

    // Limit adjustment step
    int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;
    if (nActualTimespan < params.nPowTargetTimespan / 4)
        nActualTimespan = params.nPowTargetTimespan / 4;
    if (nActualTimespan > params.nPowTargetTimespan * 4)
        nActualTimespan = params.nPowTargetTimespan * 4;

    // Retarget
    arith_uint256 bnNew;
    arith_uint256 bnOld;
    bnNew.SetCompact(pindexLast->nBits);
    bnOld = bnNew;
    // Catcoin: intermediate uint256 can overflow by 1 bit
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    bool fShift = bnNew.bits() > bnPowLimit.bits() - 1;
    if (fShift)
        bnNew >>= 1;
    bnNew *= nActualTimespan;
    bnNew /= params.nPowTargetTimespan;
    if (fShift)
        bnNew <<= 1;

    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;

    return bnNew.GetCompact();
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
