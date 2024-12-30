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

unsigned int GetNextWorkRequired_PID1238(const CBlockIndex* pindexLast, const CBlockHeader* pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);

    int64_t nActualTimespan;
    int64_t nActualTimespan8;
    int64_t nActualTimespan3;
    int64_t nActualTimespan2;
    int64_t nActualTimespan1;

    CBigNum bnNew;
    const CBlockIndex* pindexFirst8 = pindexLast;
    const CBlockIndex* pindexFirst3 = pindexLast;
    const CBlockIndex* pindexFirst2 = pindexLast;
    const CBlockIndex* pindexFirst1 = pindexLast;

    int64_t error;
    int64_t error8;
    int64_t error3;
    int64_t error2;
    int64_t error1;

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

    pindexFirst8 = pindexLast->pprev;
    pindexFirst3 = pindexLast->pprev;
    pindexFirst2 = pindexLast->pprev;
    pindexFirst1 = pindexLast->pprev;

    for (int i = 0; i < 7; i++)
        pindexFirst8 = pindexFirst8->pprev;

    for (int i = 0; i < 3; i++)
        pindexFirst3 = pindexFirst3->pprev;

    for (int i = 0; i < 2; i++)
        pindexFirst2 = pindexFirst2->pprev;

    for (int i = 0; i < 1; i++)
        pindexFirst1 = pindexFirst1->pprev;
		

	nActualTimespan8 = pindexLast->GetBlockTime() - pindexFirst8->GetBlockTime(); 	// 8 blk timespan
	nActualTimespan3 = pindexLast->GetBlockTime() - pindexFirst3->GetBlockTime(); 	// 3 blk timespan
	nActualTimespan2 = pindexLast->GetBlockTime() - pindexFirst2->GetBlockTime(); 	// 2 blk timespan
	nActualTimespan1 = pindexLast->GetBlockTime() - pindexFirst1->GetBlockTime(); 	// 1 blk timespan

	nActualTimespan = nActualTimespan8;

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

	error8 = nActualTimespan8 - params.nPowTargetSpacing;
	error3 = nActualTimespan3 - params.nPowTargetSpacing;
	error2 = nActualTimespan2 - params.nPowTargetSpacing;
	error1 = nActualTimespan1 - params.nPowTargetSpacing;

	error = error8; // default error starts at average of 8

	if(std::abs(error3) < std::abs(error)) error = error3;
	if(std::abs(error2) < std::abs(error)) error = error2;
	if(std::abs(error1) < std::abs(error)) error = error1;

    if (error >= -250 && error <= 250)
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