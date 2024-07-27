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

unsigned int GetNextWorkRequired_DigiShield(const CBlockIndex* pindexLast, const CBlockHeader* pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);
    static CBigNum bnProofOfWorkLimit(params.powLimit);

    const CBlockIndex* pindexPrev = pindexLast->pprev;
    assert(pindexPrev);
    int64_t nActualTimespan = pindexLast->GetBlockTime() - pindexPrev->GetBlockTime();

    // limit difficulty changes between 50% and 125% (human view)
    if (nActualTimespan < (params.nPowTargetSpacing - (params.nPowTargetSpacing / 4))) nActualTimespan = (params.nPowTargetSpacing - (params.nPowTargetSpacing / 4));
    if (nActualTimespan > (params.nPowTargetSpacing + (params.nPowTargetSpacing / 2))) nActualTimespan = (params.nPowTargetSpacing + (params.nPowTargetSpacing / 2));

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