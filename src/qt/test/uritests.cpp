// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "uritests.h"

#include "guiutil.h"
#include "walletmodel.h"

#include <QUrl>

void URITests::uriTests()
{
    SendCoinsRecipient rv;
    QUrl uri;
<<<<<<< HEAD
    uri.setUrl(QString("dash:XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwg?req-dontexist="));
    QVERIFY(!GUIUtil::parseBitcoinURI(uri, &rv));

    uri.setUrl(QString("dash:XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwg?dontexist="));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == QString("XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwg"));
    QVERIFY(rv.label == QString());
    QVERIFY(rv.amount == 0);

    uri.setUrl(QString("dash:XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwg?label=Some Example Address"));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == QString("XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwg"));
    QVERIFY(rv.label == QString("Some Example Address"));
    QVERIFY(rv.amount == 0);

    uri.setUrl(QString("dash:XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwg?amount=0.001"));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == QString("XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwg"));
    QVERIFY(rv.label == QString());
    QVERIFY(rv.amount == 100000);

    uri.setUrl(QString("dash:XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwg?amount=1.001"));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == QString("XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwg"));
    QVERIFY(rv.label == QString());
    QVERIFY(rv.amount == 100100000);

    uri.setUrl(QString("dash:XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwg?amount=100&label=Some Example"));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == QString("XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwg"));
=======
    uri.setUrl(QString("crowncoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?req-dontexist="));
    QVERIFY(!GUIUtil::parseCrowncoinURI(uri, &rv));

    uri.setUrl(QString("crowncoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?dontexist="));
    QVERIFY(GUIUtil::parseCrowncoinURI(uri, &rv));
    QVERIFY(rv.recipient == QString("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"));
    QVERIFY(rv.label == QString());
    QVERIFY(rv.amount == 0);

    uri.setUrl(QString("crowncoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?label=Wikipedia Example Address"));
    QVERIFY(GUIUtil::parseCrowncoinURI(uri, &rv));
    QVERIFY(rv.recipient == QString("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"));
    QVERIFY(rv.label == QString("Wikipedia Example Address"));
    QVERIFY(rv.amount == 0);

    uri.setUrl(QString("crowncoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=0.001"));
    QVERIFY(GUIUtil::parseCrowncoinURI(uri, &rv));
    QVERIFY(rv.recipient == QString("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"));
    QVERIFY(rv.label == QString());
    QVERIFY(rv.amount == 100000);

    uri.setUrl(QString("crowncoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=1.001"));
    QVERIFY(GUIUtil::parseCrowncoinURI(uri, &rv));
    QVERIFY(rv.recipient == QString("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"));
    QVERIFY(rv.label == QString());
    QVERIFY(rv.amount == 100100000);

    uri.setUrl(QString("crowncoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=100&label=Wikipedia Example"));
    QVERIFY(GUIUtil::parseCrowncoinURI(uri, &rv));
    QVERIFY(rv.recipient == QString("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"));
>>>>>>> origin/dirty-merge-dash-0.11.0
    QVERIFY(rv.amount == 10000000000LL);
    QVERIFY(rv.label == QString("Some Example"));

<<<<<<< HEAD
    uri.setUrl(QString("dash:XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwg?message=Some Example Address"));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == QString("XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwg"));
    QVERIFY(rv.label == QString());

    QVERIFY(GUIUtil::parseBitcoinURI("dash://XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwg?message=Some Example Address", &rv));
    QVERIFY(rv.address == QString("XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwg"));
    QVERIFY(rv.label == QString());

    uri.setUrl(QString("dash:XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwg?req-message=Some Example Address"));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));

    uri.setUrl(QString("dash:XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwg?amount=1,000&label=Some Example"));
    QVERIFY(!GUIUtil::parseBitcoinURI(uri, &rv));

    uri.setUrl(QString("dash:XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwg?amount=1,000.0&label=Some Example"));
    QVERIFY(!GUIUtil::parseBitcoinURI(uri, &rv));
=======
    uri.setUrl(QString("crowncoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?message=Wikipedia Example Address"));
    QVERIFY(GUIUtil::parseCrowncoinURI(uri, &rv));
    QVERIFY(rv.recipient == QString("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"));
    QVERIFY(rv.label == QString());

    QVERIFY(GUIUtil::parseCrowncoinURI("crowncoin://175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?message=Wikipedia Example Address", &rv));
    QVERIFY(rv.recipient == QString("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"));
    QVERIFY(rv.label == QString());

    uri.setUrl(QString("crowncoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?req-message=Wikipedia Example Address"));
    QVERIFY(GUIUtil::parseCrowncoinURI(uri, &rv));

    uri.setUrl(QString("crowncoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=1,000&label=Wikipedia Example"));
    QVERIFY(!GUIUtil::parseCrowncoinURI(uri, &rv));

    uri.setUrl(QString("crowncoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=1,000.0&label=Wikipedia Example"));
    QVERIFY(!GUIUtil::parseCrowncoinURI(uri, &rv));
>>>>>>> origin/dirty-merge-dash-0.11.0
}
