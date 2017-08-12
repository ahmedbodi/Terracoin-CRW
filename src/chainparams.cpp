// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Crown developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"

#include "random.h"
#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

using namespace std;
using namespace boost::assign;

struct SeedSpec6 {
    uint8_t addr[16];
    uint16_t port;
};

#include "chainparamsseeds.h"

/**
 * Main network
 */

//! Convert the pnSeeds6 array into usable address objects.
static void convertSeed6(std::vector<CAddress> &vSeedsOut, const SeedSpec6 *data, unsigned int count)
{
    // It'll only connect to one or two seed nodes because once it connects,
    // it'll get a pile of addresses with newer timestamps.
    // Seed nodes are given a random 'last seen time' of between one and two
    // weeks ago.
    const int64_t nOneWeek = 7*24*60*60;
    for (unsigned int i = 0; i < count; i++)
    {
        struct in6_addr ip;
        memcpy(&ip, data[i].addr, sizeof(ip));
        CAddress addr(CService(ip, data[i].port));
        addr.nTime = GetTime() - GetRand(nOneWeek) - nOneWeek;
        vSeedsOut.push_back(addr);
    }
}

/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

static Checkpoints::MapCheckpoints mapCheckpoints =
        boost::assign::map_list_of

            (    0, uint256S("0x00000000804bbc6a621a9dbb564ce469f492e1ccf2d70f8a6b241e26a277afa2"))
            (    1, uint256S("0x000000000fbc1c60a7610c894f98d102390e9e00cc18caced4eb4198ec0c3645"))
            (   31, uint256S("0x00000000045341e3ebdfa180e4a0f1e4da23829609517a3673b4a796714a7593"))
            (  104, uint256S("0x000000006afe30806352f2015829527dd91f19fbc2d28f799c3ad61c37746fdb"))
            (  355, uint256S("0x0000000000c0e178ddd6a8f15724f37470428c233883c302267299b21fb5d237"))
            (  721, uint256S("0x00000000027671a417f3d3eafac6d150f0b2ccba37f0b63f75bc657ec25950ed"))
            ( 2000, uint256S("0x000000000283ecd683fe30d4542929a78873df7818029793f84e9c65dc337d94"))
            ( 3000, uint256S("0x0000000000317b69ff2a56284442fede7ffa66f75d000f1cf34171ad671db4b6"))
            ( 4000, uint256S("0x00000000001190cad5d66d028b6afcf22db58d2b5c17abf2bf2e1353be13097d"))
            ( 4255, uint256S("0x000000000018b3ba5b241f3e88b4a88e580f9e7dd0fc7fc786ff22c586e53dd9"))
            ( 5631, uint256S("0x00000000001243509866938e344c0010bd88b156da27ef9d707cb1f1698f2a32"))
            ( 6000, uint256S("0x00000000000c1abfd7c29d07e23ef52631c6874e42e6a240a4d3678d9c716d81"))
            ( 7395, uint256S("0x0000000000005d8e1281d6b28fe6b504ab81e7e3ec561e97b7a98973e449f7fb"))
            ( 8001, uint256S("0x00000000001ca63707536b6dfc8ba4c5aa7fce19b6295ef73e195554cdb92d44"))
            ( 8157, uint256S("0x00000000001303998da2714abf02159f1421103e77fee3b876d69c0fa7b108d9"))
            (12311, uint256S("0x00000000002b5708fefdceb5db42cd2135eaf23f23a95c285e8f310262f8d639"))
            (13224, uint256S("0x00000000000765c69f777ccbc44fab23edab9126f1b4ec5078450aebc3809c36"))
            (14401, uint256S("0x0000000000388541b88c57883a480fd6cfa7b93f68e0c71538b08b2c4d875fa2"))
            (15238, uint256S("0x000000000000ae09d46bc1a9c5ca4c7b5e51bf23d3108926daa140d64355d390"))
            (18426, uint256S("0x00000000001fb1c075dbfa27f7ba83928a2d35152ccae59c742f698fb8cb8108"))
            (19114, uint256S("0x000000000022224f57adecffdc8f5cffb3b932838310aefdd12aaabcc6122259"))
            (20124, uint256S("0x00000000002374e0e1fcee28b520dff3f3e86cb7ff7afdea112aaf2002101900"))
            (21711, uint256S("0x00000000002189b0ae139b8c449bbcb99d520b8a798b7e0f0ff8ab8539e9bcb4"))
            (22100, uint256S("0x0000000000142ace7d8db003da69191896986c5564e604e3100d14c17daaf90f"))
            (22566, uint256S("0x00000000000c28dc052d277d18e104e4e63c53e4018273b3af49f772af205d43"))
            (24076, uint256S("0x00000000000522702c7f0ee6fa2ce3978cc0f3056ecc73d8cde1035891c5c4d5"))
            (25372, uint256S("0x0000000000202428a01ad6b8a2e256162b5bba35efd1e7f45dc42dbf5861f784"))
            (25538, uint256S("0x00000000002faa5586493e3821d90482348b0462d625d03d086a4a2a2301f6ef"))
            (26814, uint256S("0x0000000000179b0ed2a7d4390ff2c6213f1c522790b4e084a4e2036b53e6765b"))
            (28326, uint256S("0x0000000000141af96e4ab491d6534a6740491d62799b1669418d33bb007acfd7"))
            (28951, uint256S("0x00000000002404c991c7f9e1d641e8938f1ab704a3f9e1d22589d817948a202f"))
            (30765, uint256S("0x00000000004be710d96035855f406c1393c922d5948d82dce494368e3993c76a"))
            (32122, uint256S("0x0000000000109367e18d9c9762cdb8bfb3c524628ad2ce9bcb02a6a9bfa13e39"))
            (33526, uint256S("0x0000000000406137d7afb03df768f0c6d7ab1efdbc14325d018b62b7ef17fa1c"))
            (34310, uint256S("0x0000000000325205f89b7685639fc997248cbaf8dbf2d53ad2e00f98948de58c"))
            (35277, uint256S("0x00000000000214b28bc7b1ea230417442417d2381673bcec4ac3ef87c6d0b9f8"))
            (36341, uint256S("0x0000000000143a6fd244037ebf301c6898f34c6db428916057eadddec4e35061"))
            (51013, uint256S("0x00000000002afdd383affb15708fd329feaa68fdabe477bce4eceec7525dc7f2"))
            (63421, uint256S("0x000000000020867e3050e7f4b4402c578215a2174723f614d31d5f21eb61a173"))
            (67755, uint256S("0x00000000001151bbacf6f169312aaa0c71e0f71765ceb4e8ebffabc219993ba7"))
            (69198, uint256S("0x000000000041498e3911ccbd9aee327bb9bc58dcdf4cd51956909ce5575fccf5"))
            (71945, uint256S("0x00000000006d1cb2ad6700614c54a962bbe7d6baeb02c227b9dda2e0a59077da"))
            (74654, uint256S("0x00000000001b274b44531f13d5a023ae0450e765e403893c64aea7c6c21eec8e"))
            (77505, uint256S("0x00000000003be70f239212ba753a1fdd985fee027e276556619eeb40a771c151"))
            (95971, uint256S("0x000000000009d877e435995db1565558e30a7f8ee220cad5d0a4a055d0ebb8bf"))
            (106681, uint256S("0x000000000000d081d43eb74429e7344f18c4300796faaa54f5432c4976a9fc2b"))
            (106685, uint256S("0x00000000000017e88ad9cf01e74941a134434bf0c39ef254498e4cbb754b604f"))
            (106693, uint256S("0x00000000000271eb870d1573f3c1e1ba4c33a56f80333b89219d8affb2a8dadc"))
            (106715, uint256S("0x0000000000012d109bfe2a5b464defb0214b5b25090acb9cc0fd9ca054c53d6a"))
            (106725, uint256S("0x000000000007c734700d0be1f0c2358f57a009752257da8dcc2206185e9a580a"))
            (106748, uint256S("0x000000000000148fc833528722f41af106c08ed2da67e777f5a6b8ec2d60d695"))
            (106753, uint256S("0x0000000000003cb9976d3785c2960728bdd67d4ddfce640682b9c9c4df8582d9"))
            (106759, uint256S("0x000000000002ed231df0f8c4f21f2a73eeacbbc88f411b438ad4fd4b60418c42"))
            (107368, uint256S("0x000000000009062fe1b4c0654b3d152282545aa8beba3c0e4981d9dfa71b1eaa"))
            (108106, uint256S("0x00000000000282bf4e2bd0571c42165a67ffede3b81f2387e301369162107020"))
            (110197, uint256S("0x0000000000002d863064910c8964f5d8e2883aca9760c19368fe043263e2bfdd"))
            (137162, uint256S("0x00000000000342fd6e38765cc6f8f56d60c49e3e9522a54d99f561d35800a293"))
            (175950, uint256S("0x00000000000099c20a1fab3ace0421aa7038ca4fef541211aea8ed458b70a930"))
            (176570, uint256S("0x000000000000144a313379e6b76827b7959fb79322ebfd2bd9bb1ec04b8a015c"))
            (187891, uint256S("0x00000000000081f7748611af5ce18f40ab8affcabe39d1c68a038ecc0eb04310"))
            (191101, uint256S("0x000000000000250376b9fca7d353be9de6cc6266368d84e9bb8ab7ed06a4af27"))
            (263883, uint256S("0x0000000000000301007ab6d4ecb5cc223e80fb7e057d42f6963ba95b3b45981f"))
            (318300, uint256S("0x0000000000000bed2da6a46a698932caacf7fc164767b13c283b246c06440fb5"))
            (346805, uint256S("0x0000000000001054a0e53771c81dc9d057f8b2e6fcbf2069634807b89124c4f9"))
        ;
static const Checkpoints::CCheckpointData data = {
        &mapCheckpoints,
        1408905730, // * UNIX timestamp of last checkpoint block
        1152752,    // * total number of transactions between genesis and last checkpoint
                    //   (the tx=... number in the SetBestChain debug.log lines)
        1540        // * estimated number of transactions per day after checkpoint
    };

static Checkpoints::MapCheckpoints mapCheckpointsTestnet =
        boost::assign::map_list_of
        ( 0, uint256S("0x000000004daeaebf6182d09b7b40b81bc72caab1a13c79cef2669b0b5686b7b8"))
        ;
static const Checkpoints::CCheckpointData dataTestnet = {
        &mapCheckpointsTestnet,
        1483492562, // * UNIX timestamp of last checkpoint block
        0,          // * total number of transactions between genesis and last checkpoint
                    //   (the tx=... number in the SetBestChain debug.log lines)
        0           // * estimated number of transactions per day after checkpoint
    };

static Checkpoints::MapCheckpoints mapCheckpointsRegtest =
        boost::assign::map_list_of
        ( 0, uint256S("0x231de73ec08234a4adff3c71e57271a13fa73f5ae1ca6b0ded89275e557a6207"))
        ;
static const Checkpoints::CCheckpointData dataRegtest = {
        &mapCheckpointsRegtest,
        1296688602, // * UNIX timestamp of last checkpoint block
        0,          // * total number of transactions between genesis and last checkpoint
                    //   (the tx=... number in the SetBestChain debug.log lines)
        0           // * estimated number of transactions per day after checkpoint
    };

class CMainParams : public CChainParams {
public:
    CMainParams() {
        networkID = CBaseChainParams::MAIN;
        strNetworkID = "main";
        /** 
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 4-byte int at any alignment.
         */
        pchMessageStart[0] = 0x42;
        pchMessageStart[1] = 0xba;
        pchMessageStart[2] = 0xbe;
        pchMessageStart[3] = 0x56;
        vAlertPubKey = ParseHex("04977aae0411f4e1757e8682c87ee79180ad577ef0351054e6cda5c9381fcd8c7333e88ac250d3ab3e3aafd5d1c1d946f2ca62372db7f35c84398a878aa145f09a");
        nDefaultPort = 13333;
        bnProofOfWorkLimit = ~arith_uint256(0) >> 32;  // Terracoin starting difficulty is 1 / 2^12
        nSubsidyHalvingInterval = 1050000;
        nEnforceBlockUpgradeMajority = 750;
        nRejectBlockOutdatedMajority = 950;
        nToCheckBlockUpgradeMajority = 1000;
        nMinerThreads = 0;
        nTargetTimespan = 60 * 60; // Terracoin: 2 weeks
        nTargetSpacing = 2 * 60; // Terracoin: 1 minutes
        nMaxTipAge = 6 * 60 * 60; 

        /**
         * Build the genesis block. Note that the output of the genesis coinbase cannot
         * be spent as it did not originally exist in the database.
         * 
         * CBlock(hash=00000ffd590b14, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=e0028e, nTime=1390095618, nBits=1e0ffff0, nNonce=28917698, vtx=1)
         *   CTransaction(hash=e0028e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
         *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d01044c5957697265642030392f4a616e2f3230313420546865204772616e64204578706572696d656e7420476f6573204c6976653a204f76657273746f636b2e636f6d204973204e6f7720416363657074696e6720426974636f696e73)
         *     CTxOut(nValue=50.00000000, scriptPubKey=0xA9037BAC7050C479B121CF)
         *   vMerkleTree: e0028e
         */
        const char* pszTimestamp = "June 4th 1978 - March 6th 2009 ; Rest In Peace, Stephanie.";
        CMutableTransaction txNew;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].nValue = 50 * COIN;
        txNew.vout[0].scriptPubKey = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock.SetNull();
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nVersion.SetGenesisVersion(1);
        genesis.nTime    = 1351242683;
        genesis.nBits    = 0x1d00ffff;
        genesis.nNonce   = 2820375594;

        hashGenesisBlock = genesis.GetHash();

        assert(hashGenesisBlock == uint256S("0x00000000804bbc6a621a9dbb564ce469f492e1ccf2d70f8a6b241e26a277afa2"));
        assert(genesis.hashMerkleRoot == uint256S("0x0f8b09f93803b067580c16c3f3a6aaa901be06ad892cea9f02d8a4f93628f196"));

        vSeeds.push_back(CDNSSeedData("seed.terracoin.io", "seed.terracoin.io"));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,0);                    // Terracoin addresses start with 'X'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,5);                    // Terracoin script addresses start with '7'
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,128);                    // Terracoin private keys start with '7' or 'X'
        base58Prefixes[EXT_PUBLIC_KEY] = list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_COIN_TYPE]  = list_of(0x80000005).convert_to_container<std::vector<unsigned char> >();             // Terracoin BIP44 coin type is '5'

        convertSeed6(vFixedSeeds, pnSeed6_main, ARRAYLEN(pnSeed6_main));

        fRequireRPCPassword = true;
        fMiningRequiresPeers = true;
        fAllowMinDifficultyBlocks = false;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = false;

        nPoolMaxTransactions = 3;
        strSporkKey = "0440409BDACDCE03BFB6D5F16E2D414953038996B49BEE6697CFA400A0001D0837C885C5B57DAD10E5CAAAE36EE975005CC6CBD7001A2A8DE76FF12185904A9BB1";
        strDarksendPoolDummyAddress = "18WTcWvwrNnfqeQAn6th9QQ2EpnXMq5Th8";
        nStartThronePayments = 1403728576; //Wed, 25 Jun 2014 20:36:16 GMT
    }

    const Checkpoints::CCheckpointData& Checkpoints() const 
    {
        return data;
    }
    int AuxpowStartHeight() const
    {
        return 833000;
    }

    bool StrictChainId() const
    {
        return true;
    }

    bool AllowLegacyBlocks(unsigned nHeight) const
    {
        return static_cast<int> (nHeight) < AuxpowStartHeight();
    }
};
static CMainParams mainParams;

/**
 * Testnet (v4)
 */
class CTestNetParams : public CMainParams {
public:
    CTestNetParams() {
        networkID = CBaseChainParams::TESTNET;
        strNetworkID = "test";
        pchMessageStart[0] = 0x41;
        pchMessageStart[1] = 0xba;
        pchMessageStart[2] = 0xbe;
		pchMessageStart[3] = 0x56;
        vAlertPubKey = ParseHex("04517d8a699cb43d3938d7b24faaff7cda448ca4ea267723ba614784de661949bf632d6304316b244646dea079735b9a6fc4af804efb4752075b9fe2245e14e412");
        nDefaultPort = 23333;
        nEnforceBlockUpgradeMajority = 51;
        nRejectBlockOutdatedMajority = 75;
        nToCheckBlockUpgradeMajority = 100;
        nMinerThreads = 0;
        nMaxTipAge = 0x7fffffff;

        //! Modify the testnet genesis block so the timestamp is valid for a later start.
        genesis.nTime = 1354965534;
        genesis.nNonce = 1178774204;

        hashGenesisBlock = genesis.GetHash();
        assert(hashGenesisBlock == uint256S("0x00000000d64b490e447fb522682bfa6bcb27886ed1a94d7a4856fb92ab130875"));

        vFixedSeeds.clear();
        vSeeds.push_back(CDNSSeedData("testnetseed.terracoin.io", "testnetseed.terracoin.io"))();

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);                    // Testnet terracoin addresses start with 'x' or 'y'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);                    // Testnet terracoin script addresses start with '8' or '9'
        base58Prefixes[SECRET_KEY]     = std::vector<unsigned char>(1,239);                    // Testnet private keys start with '9' or 'c' (Bitcoin defaults)
        base58Prefixes[EXT_PUBLIC_KEY] = list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_COIN_TYPE]  = list_of(0x80000001).convert_to_container<std::vector<unsigned char> >();             // Testnet terracoin BIP44 coin type is '5' (All coin's testnet default)

        convertSeed6(vFixedSeeds, pnSeed6_test, ARRAYLEN(pnSeed6_test));

        fRequireRPCPassword = true;
        fMiningRequiresPeers = true;
        fAllowMinDifficultyBlocks = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;

        nPoolMaxTransactions = 2;
        strSporkKey = "0440409BDACDCE03BFB6D5F16E2D414953038996B49BEE6697CFA400A0001D0837C885C5B57DAD10E5CAAAE36EE975005CC6CBD7001A2A8DE76FF12185904A9BB1";
        strDarksendPoolDummyAddress = "y1EZuxhhNMAUofTBEeLqGE1bJrpC2TWRNp";
        nStartThronePayments = 1420837558; //Fri, 09 Jan 2015 21:05:58 GMT
    }
    const Checkpoints::CCheckpointData& Checkpoints() const 
    {
        return dataTestnet;
    }
    int AuxpowStartHeight() const
    {
        return 0;
    }

    bool StrictChainId() const
    {
        return false;
    }

    bool AllowLegacyBlocks(unsigned) const
    {
        return true;
    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CTestNetParams {
public:
    CRegTestParams() {
        networkID = CBaseChainParams::REGTEST;
        strNetworkID = "regtest";
        pchMessageStart[0] = 0xfb;
        pchMessageStart[1] = 0xae;
        pchMessageStart[2] = 0xc6;
        pchMessageStart[3] = 0xdf;
        nSubsidyHalvingInterval = 150;
        nEnforceBlockUpgradeMajority = 750;
        nRejectBlockOutdatedMajority = 950;
        nToCheckBlockUpgradeMajority = 1000;
        nMinerThreads = 1;
        nTargetTimespan = 14 * 24 * 60 * 60; // Terracoin: 2 weeks
        nTargetSpacing = 1 * 60; // Terracoin: 1 minutes
        bnProofOfWorkLimit = ~arith_uint256(0) >> 1;
        nMaxTipAge = 6 * 60 * 60;
        genesis.nTime = 1296688602;
        genesis.nBits = 0x207fffff;
        genesis.nNonce = 1;
        hashGenesisBlock = genesis.GetHash();
        nDefaultPort = 19445;
        //assert(hashGenesisBlock == uint256S("0x231de73ec08234a4adff3c71e57271a13fa73f5ae1ca6b0ded89275e557a6207"));

        vFixedSeeds.clear(); //! Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();  //! Regtest mode doesn't have any DNS seeds.

        fRequireRPCPassword = false;
        fMiningRequiresPeers = false;
        fAllowMinDifficultyBlocks = true;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;
    }
    const Checkpoints::CCheckpointData& Checkpoints() const 
    {
        return dataRegtest;
    }

    bool StrictChainId() const
    {
        return true;
    }

    bool AllowLegacyBlocks(unsigned) const
    {
        return false;
    }
};
static CRegTestParams regTestParams;

/**
 * Unit test
 */
class CUnitTestParams : public CMainParams, public CModifiableParams {
public:
    CUnitTestParams() {
        networkID = CBaseChainParams::UNITTEST;
        strNetworkID = "unittest";
        nDefaultPort = 18445;
        vFixedSeeds.clear(); //! Unit test mode doesn't have any fixed seeds.
        vSeeds.clear();  //! Unit test mode doesn't have any DNS seeds.

        fRequireRPCPassword = false;
        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fAllowMinDifficultyBlocks = false;
        fMineBlocksOnDemand = true;
    }

    const Checkpoints::CCheckpointData& Checkpoints() const 
    {
        // UnitTest share the same checkpoints as MAIN
        return data;
    }

    /* StrictChainId() = true inherited from CMainParams.  */

    bool AllowLegacyBlocks(unsigned) const
    {
        /* Allow legacy blocks.  This is to make the unit tests that
           rely on loading predefined block data work.  (In particular,
           miner_tests.cpp.)  */
        return true;
    }

    //! Published setters to allow changing values in unit test cases
    virtual void setSubsidyHalvingInterval(int anSubsidyHalvingInterval)  { nSubsidyHalvingInterval=anSubsidyHalvingInterval; }
    virtual void setEnforceBlockUpgradeMajority(int anEnforceBlockUpgradeMajority)  { nEnforceBlockUpgradeMajority=anEnforceBlockUpgradeMajority; }
    virtual void setRejectBlockOutdatedMajority(int anRejectBlockOutdatedMajority)  { nRejectBlockOutdatedMajority=anRejectBlockOutdatedMajority; }
    virtual void setToCheckBlockUpgradeMajority(int anToCheckBlockUpgradeMajority)  { nToCheckBlockUpgradeMajority=anToCheckBlockUpgradeMajority; }
    virtual void setDefaultConsistencyChecks(bool afDefaultConsistencyChecks)  { fDefaultConsistencyChecks=afDefaultConsistencyChecks; }
    virtual void setAllowMinDifficultyBlocks(bool afAllowMinDifficultyBlocks) {  fAllowMinDifficultyBlocks=afAllowMinDifficultyBlocks; }
    virtual void setProofOfWorkLimit(const arith_uint256& limit) { bnProofOfWorkLimit = limit; }
};
static CUnitTestParams unitTestParams;


static CChainParams *pCurrentParams = 0;

CModifiableParams *ModifiableParams()
{
   assert(pCurrentParams);
   assert(pCurrentParams==&unitTestParams);
   return (CModifiableParams*)&unitTestParams;
}

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams &Params(CBaseChainParams::Network network) {
    switch (network) {
        case CBaseChainParams::MAIN:
            return mainParams;
        case CBaseChainParams::TESTNET:
            return testNetParams;
        case CBaseChainParams::REGTEST:
            return regTestParams;
        case CBaseChainParams::UNITTEST:
            return unitTestParams;
        default:
            assert(false && "Unimplemented network");
            return mainParams;
    }
}

void SelectParams(CBaseChainParams::Network network) {
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}

bool SelectParamsFromCommandLine()
{
    CBaseChainParams::Network network = NetworkIdFromCommandLine();
    if (network == CBaseChainParams::MAX_NETWORK_TYPES)
        return false;

    SelectParams(network);
    return true;
}
