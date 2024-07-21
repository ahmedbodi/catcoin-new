// Copyright (c) 2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <key.h>
#include <key_io.h>
#include <script/standard.h>
#include <test/util/setup_common.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/wallet.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(scriptpubkeyman_tests, BasicTestingSetup)

// Test LegacyScriptPubKeyMan::CanProvide behavior, making sure it returns true
// for recognized scripts even when keys may not be available for signing.
BOOST_AUTO_TEST_CASE(CanProvide)
{
    // Set up wallet and keyman variables.
    NodeContext node;
    std::unique_ptr<interfaces::Chain> chain = interfaces::MakeChain(node);
    CWallet wallet(chain.get(), "", CreateDummyWalletDatabase());
    LegacyScriptPubKeyMan& keyman = *wallet.GetOrCreateLegacyScriptPubKeyMan();

    // Make a 1 of 2 multisig script
    std::vector<CKey> keys(2);
    std::vector<CPubKey> pubkeys;
    for (CKey& key : keys) {
        key.MakeNewKey(true);
        pubkeys.emplace_back(key.GetPubKey());
    }
    CScript multisig_script = GetScriptForMultisig(1, pubkeys);
    CScript p2sh_script = GetScriptForDestination(ScriptHash(multisig_script));
    SignatureData data;

    // Verify the p2sh(multisig) script is not recognized until the multisig
    // script is added to the keystore to make it solvable
    BOOST_CHECK(!keyman.CanProvide(p2sh_script, data));
    keyman.AddCScript(multisig_script);
    BOOST_CHECK(keyman.CanProvide(p2sh_script, data));
}

BOOST_AUTO_TEST_CASE(StealthAddresses)
{
    // Set up wallet and keyman variables.
    NodeContext node;
    std::unique_ptr<interfaces::Chain> chain = interfaces::MakeChain(node);
    CWallet wallet(chain.get(), "", CreateMockWalletDatabase());
    wallet.SetMinVersion(WalletFeature::FEATURE_HD_SPLIT);
    LegacyScriptPubKeyMan& keyman = *wallet.GetOrCreateLegacyScriptPubKeyMan();

    // Set HD seed
    CKey key = DecodeSecret("P8QoLM4Ei1x2b9qPkh4Bkssx1WwyGqM7mt4GuC7jTRBue4RBvFFo");
    CPubKey seed = keyman.DeriveNewSeed(key);
    keyman.SetHDSeed(seed);
    keyman.TopUp();

    // Check generated MWEB keychain
    mw::Keychain::Ptr mweb_keychain = keyman.GetMWEBKeychain();
    BOOST_CHECK(mweb_keychain != nullptr);
    BOOST_CHECK(mweb_keychain->GetSpendSecret().ToHex() == "7e0a881a7598dd7a3f64e0a348bb0344b880673da4b60fb19b0a86f8b1dbbd89");
    BOOST_CHECK(mweb_keychain->GetScanSecret().ToHex() == "12857099b301325ff9dac608814ee0a0386ab6f31724c83ace566b304b5d93d5");

    // Check "change" (idx=0) address is USED
    StealthAddress change_address = mweb_keychain->GetStealthAddress(0);
    BOOST_CHECK(EncodeDestination(change_address) == "catmweb1qqfp2dcdde24gm59znyvlw72wh6xq9hmm8wzycduzcr95xuxmlund7q4kf7ttrnqkvy2vqxxazuc5fsvh6ug3ypywey92u0q9243k5zt26gwcuu9f");
    BOOST_CHECK(keyman.IsMine(change_address) == ISMINE_SPENDABLE);
    BOOST_CHECK(keyman.GetAllReserveKeys().find(change_address.B().GetID()) == keyman.GetAllReserveKeys().end());
    BOOST_CHECK(*keyman.GetMetadata(change_address)->mweb_index == 0);

    // Check "peg-in" (idx=1) address is USED
    StealthAddress pegin_address = mweb_keychain->GetStealthAddress(1);
    BOOST_CHECK(EncodeDestination(pegin_address) == "catmweb1qqv65wxrqccudwrna9w4fyd8xregsnwmvqzwzu8kjuy7cyxzq8upkgq5c6emh06xm0wfh2tuz24e9g7mm2y8mhywu7p8sy699rx23mywaggwrd62r");
    BOOST_CHECK(keyman.IsMine(pegin_address) == ISMINE_SPENDABLE);
    BOOST_CHECK(keyman.GetAllReserveKeys().find(pegin_address.B().GetID()) == keyman.GetAllReserveKeys().end());
    BOOST_CHECK(*keyman.GetMetadata(pegin_address)->mweb_index == 1);

    // Check first receive (idx=2) address is UNUSED
    StealthAddress receive_address = mweb_keychain->GetStealthAddress(2);
    BOOST_CHECK(EncodeDestination(receive_address) == "catmweb1qq0zdea368ezsxa9x5wshcfmszq4epuf62ys4w72g3nseyat43xfwkqj8ery4wjkxuc3cy2epgt6z9p8eze99grfyljt574y30lryx0atgc326rfj");
    BOOST_CHECK(keyman.IsMine(receive_address) == ISMINE_SPENDABLE);
    BOOST_CHECK(keyman.GetAllReserveKeys().find(receive_address.B().GetID()) != keyman.GetAllReserveKeys().end());
    BOOST_CHECK(*keyman.GetMetadata(receive_address)->mweb_index == 2);

    BOOST_CHECK(keyman.GetHDChain().nMWEBIndexCounter == 1002);
}

BOOST_AUTO_TEST_SUITE_END()
