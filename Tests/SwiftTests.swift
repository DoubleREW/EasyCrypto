//
//  SwiftTests.swift
//  EasyCrypto
//
//  Created by Fausto Ristagno on 16/09/15.
//  Copyright © 2015 Fausto Ristagno. All rights reserved.
//

import XCTest
import EasyCrypto

class SwiftTests: XCTestCase {

    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }

    func testDigests() {
        let s = "EasyCrypto"
        
        let md2 = ECMd2(string: s)
        let md4 = ECMd4(string: s)
        let md5 = ECMd5(string: s)
        let sha1 = ECSha1(string: s)
        let sha224 = ECSha224(string: s)
        let sha256 = ECSha256(string: s)
        let sha384 = ECSha384(string: s)
        let sha512 = ECSha512(string: s)
        
        XCTAssertEqual(md2.hexDigest,       "bf3867aff7010d0127391c8cfadbd4d5")
        XCTAssertEqual(md4.hexDigest,       "dcccc73b4595a81c592ae57fdb324e00")
        XCTAssertEqual(md5.hexDigest,       "4ea4d3130bb52ef6ef326c7534c1d04b")
        XCTAssertEqual(sha1.hexDigest,      "5c88e9b97ce1079e12dce01507e6f77ab21dcc91")
        XCTAssertEqual(sha224.hexDigest,    "5249ca809eb4964d86e794a1a1e4a49816e4dfd0e22adf9b1bb8c06b")
        XCTAssertEqual(sha256.hexDigest,    "82219fadb62a4fbf686e767f79a779b675bf304b4f9ebace309d53d68756b64b")
        XCTAssertEqual(sha384.hexDigest,    "d8b440aed74bc59290fd579f19b667e28efa07992fc35c18a1c06b71189d5ea7d4c5c38c723b56a51aab3d78c9c5ea37")
        XCTAssertEqual(sha512.hexDigest,    "20fa40952952d7e9f4b42f8bd8e39b5c77418b98a1dd558747f4f57d46ac07f17fcea9c59c62b51051aa36902a99ea2b4508fb489724da259f0236174721c01d")
        
    }

}
