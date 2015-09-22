//
//  SwiftTests.swift
//  EasyCrypto
//
//  Created by Fausto Ristagno on 16/09/15.
//  Copyright © 2015 Fausto Ristagno. All rights reserved.
//

import XCTest
import EasyCrypto

class HashTests: XCTestCase {
    let message = "EasyCrypto"
    var data: NSData!
    
    var md2: ECHashMD2!
    var md4: ECHashMD4!
    var md5: ECHashMD5!
    var sha1: ECHashSHA1!
    var sha224: ECHashSHA224!
    var sha256: ECHashSHA256!
    var sha384: ECHashSHA384!
    var sha512: ECHashSHA512!
    
    
    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
        self.data = self.message.dataUsingEncoding(NSUTF8StringEncoding)
        
        self.md2 = ECHashMD2(string: self.message)
        self.md4 = ECHashMD4(string: message)
        self.md5 = ECHashMD5(string: message)
        self.sha1 = ECHashSHA1(string: message)
        self.sha224 = ECHashSHA224(string: message)
        self.sha256 = ECHashSHA256(string: message)
        self.sha384 = ECHashSHA384(string: message)
        self.sha512 = ECHashSHA512(string: message)
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    
    func testDigestData() {
        XCTAssertNotNil(md2.digest)
        XCTAssertNotNil(md4.digest)
        XCTAssertNotNil(md5.digest)
        XCTAssertNotNil(sha1.digest)
        XCTAssertNotNil(sha224.digest)
        XCTAssertNotNil(sha256.digest)
        XCTAssertNotNil(sha384.digest)
        XCTAssertNotNil(sha512.digest)
    }

    func testDigestHex() {
        XCTAssertEqual(md2.hexDigest,       "bf3867aff7010d0127391c8cfadbd4d5")
        XCTAssertEqual(md4.hexDigest,       "dcccc73b4595a81c592ae57fdb324e00")
        XCTAssertEqual(md5.hexDigest,       "4ea4d3130bb52ef6ef326c7534c1d04b")
        XCTAssertEqual(sha1.hexDigest,      "5c88e9b97ce1079e12dce01507e6f77ab21dcc91")
        XCTAssertEqual(sha224.hexDigest,    "5249ca809eb4964d86e794a1a1e4a49816e4dfd0e22adf9b1bb8c06b")
        XCTAssertEqual(sha256.hexDigest,    "82219fadb62a4fbf686e767f79a779b675bf304b4f9ebace309d53d68756b64b")
        XCTAssertEqual(sha384.hexDigest,    "d8b440aed74bc59290fd579f19b667e28efa07992fc35c18a1c06b71189d5ea7d4c5c38c723b56a51aab3d78c9c5ea37")
        XCTAssertEqual(sha512.hexDigest,    "20fa40952952d7e9f4b42f8bd8e39b5c77418b98a1dd558747f4f57d46ac07f17fcea9c59c62b51051aa36902a99ea2b4508fb489724da259f0236174721c01d")
    }
    
    func testDigestLength() {
        XCTAssertEqual(md2.digest.length,       md2.digestLength)
        XCTAssertEqual(md4.digest.length,       md4.digestLength)
        XCTAssertEqual(md5.digest.length,       md5.digestLength)
        XCTAssertEqual(sha1.digest.length,      sha1.digestLength)
        XCTAssertEqual(sha224.digest.length,    sha224.digestLength)
        XCTAssertEqual(sha256.digest.length,    sha256.digestLength)
        XCTAssertEqual(sha384.digest.length,    sha384.digestLength)
        XCTAssertEqual(sha512.digest.length,    sha512.digestLength)
    }
    
    func testHashStringExtension() {
        XCTAssertEqual(md2.digest,      self.message.md2().digest)
        XCTAssertEqual(md4.digest,      self.message.md4().digest)
        XCTAssertEqual(md5.digest,      self.message.md5().digest)
        XCTAssertEqual(sha1.digest,     self.message.sha1().digest)
        XCTAssertEqual(sha224.digest,   self.message.sha224().digest)
        XCTAssertEqual(sha256.digest,   self.message.sha256().digest)
        XCTAssertEqual(sha384.digest,   self.message.sha384().digest)
        XCTAssertEqual(sha512.digest,   self.message.sha512().digest)
    }
    
    func testHashNSStringExtension() {
        XCTAssertEqual(md2.digest,      (self.message as NSString).md2().digest)
        XCTAssertEqual(md4.digest,      (self.message as NSString).md4().digest)
        XCTAssertEqual(md5.digest,      (self.message as NSString).md5().digest)
        XCTAssertEqual(sha1.digest,     (self.message as NSString).sha1().digest)
        XCTAssertEqual(sha224.digest,   (self.message as NSString).sha224().digest)
        XCTAssertEqual(sha256.digest,   (self.message as NSString).sha256().digest)
        XCTAssertEqual(sha384.digest,   (self.message as NSString).sha384().digest)
        XCTAssertEqual(sha512.digest,   (self.message as NSString).sha512().digest)
    }
    
    func testHashNSDataExtension() {
        XCTAssertEqual(md2.digest,      self.data.md2().digest)
        XCTAssertEqual(md4.digest,      self.data.md4().digest)
        XCTAssertEqual(md5.digest,      self.data.md5().digest)
        XCTAssertEqual(sha1.digest,     self.data.sha1().digest)
        XCTAssertEqual(sha224.digest,   self.data.sha224().digest)
        XCTAssertEqual(sha256.digest,   self.data.sha256().digest)
        XCTAssertEqual(sha384.digest,   self.data.sha384().digest)
        XCTAssertEqual(sha512.digest,   self.data.sha512().digest)
    }
}
