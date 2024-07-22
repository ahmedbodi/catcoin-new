// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparamsbase.h>

#include <tinyformat.h>
#include <util/system.h>
#include <util/memory.h>

#include <assert.h>

const std::string CBaseChainParams::MAIN = "main";
const std::string CBaseChainParams::TESTNET1 = "testnet1";
const std::string CBaseChainParams::TESTNET2 = "testnet2";
const std::string CBaseChainParams::TESTNET3 = "testnet3";
const std::string CBaseChainParams::TESTNET4 = "testnet4";
const std::string CBaseChainParams::TESTNET5 = "testnet5";
const std::string CBaseChainParams::SIGNET = "signet";
const std::string CBaseChainParams::REGTEST = "regtest";

void SetupChainParamsBaseOptions(ArgsManager& argsman)
{
    argsman.AddArg("-chain=<chain>", "Use the chain <chain> (default: main). Allowed values: main, test1, test2, test3, test4, test5 signet, regtest", ArgsManager::ALLOW_ANY, OptionsCategory::CHAINPARAMS);
    argsman.AddArg("-regtest", "Enter regression test mode, which uses a special chain in which blocks can be solved instantly. "
                 "This is intended for regression testing tools and app development. Equivalent to -chain=regtest.", ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::CHAINPARAMS);
    argsman.AddArg("-segwitheight=<n>", "Set the activation height of segwit. -1 to disable. (regtest-only)", ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-testnet1", "Use the test chain. Equivalent to -chain=testnet1.", ArgsManager::ALLOW_ANY, OptionsCategory::CHAINPARAMS);
    argsman.AddArg("-testnet2", "Use the test chain. Equivalent to -chain=testnet2.", ArgsManager::ALLOW_ANY, OptionsCategory::CHAINPARAMS);
    argsman.AddArg("-testnet3", "Use the test chain. Equivalent to -chain=testnet3.", ArgsManager::ALLOW_ANY, OptionsCategory::CHAINPARAMS);
    argsman.AddArg("-testnet4", "Use the test chain. Equivalent to -chain=testnet4.", ArgsManager::ALLOW_ANY, OptionsCategory::CHAINPARAMS);
    argsman.AddArg("-testnet5", "Use the test chain. Equivalent to -chain=testnet5.", ArgsManager::ALLOW_ANY, OptionsCategory::CHAINPARAMS);
    argsman.AddArg("-vbparams=deployment:start:end[:start_height:end_height]", "Use given start/end times and start/end block heights for specified version bits deployment (regtest-only)", ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::CHAINPARAMS);
    argsman.AddArg("-signet", "Use the signet chain. Equivalent to -chain=signet. Note that the network is defined by the -signetchallenge parameter", ArgsManager::ALLOW_ANY, OptionsCategory::CHAINPARAMS);
    argsman.AddArg("-signetchallenge", "Blocks must satisfy the given script to be considered valid (only for signet networks; defaults to the global default signet test network challenge)", ArgsManager::ALLOW_STRING, OptionsCategory::CHAINPARAMS);
    argsman.AddArg("-signetseednode", "Specify a seed node for the signet network, in the hostname[:port] format, e.g. sig.net:1234 (may be used multiple times to specify multiple seed nodes; defaults to the global default signet test network seed node(s))", ArgsManager::ALLOW_STRING, OptionsCategory::CHAINPARAMS);
}

static std::unique_ptr<CBaseChainParams> globalChainBaseParams;

const CBaseChainParams& BaseParams()
{
    assert(globalChainBaseParams);
    return *globalChainBaseParams;
}

/**
 * Port numbers for incoming Tor connections (8334, 18334, 38334, 18445) have
 * been chosen arbitrarily to keep ranges of used ports tight.
 */
std::unique_ptr<CBaseChainParams> CreateBaseChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN) {
        return MakeUnique<CBaseChainParams>("", 9932, 9335); // https://github.com/CatcoinOfficial/CatcoinRelease/blob/c69cc7050a6a1e1e6aa8c34bac2c1f8dad0037a1/src/bitcoinrpc.cpp#L42C52-L42C56
    } else if (chain == CBaseChainParams::TESTNET1) {
        return MakeUnique<CBaseChainParams>("testnet1", 19332, 19335);
    } else if (chain == CBaseChainParams::TESTNET2) {
        return MakeUnique<CBaseChainParams>("testnet2", 18332, 18335);
    } else if (chain == CBaseChainParams::TESTNET3) {
        return MakeUnique<CBaseChainParams>("testnet3", 17332, 17335);
    } else if (chain == CBaseChainParams::TESTNET4) {
        return MakeUnique<CBaseChainParams>("testnet4", 16332, 16335);
    } else if (chain == CBaseChainParams::TESTNET5) {
        return MakeUnique<CBaseChainParams>("testnet5", 15332, 15335);
    } else if (chain == CBaseChainParams::SIGNET) {
        return MakeUnique<CBaseChainParams>("signet", 39332, 39335);
    } else if (chain == CBaseChainParams::REGTEST) {
        return MakeUnique<CBaseChainParams>("regtest", 49332, 49335);
    }
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectBaseParams(const std::string& chain)
{
    globalChainBaseParams = CreateBaseChainParams(chain);
    gArgs.SelectConfigNetwork(chain);
}
