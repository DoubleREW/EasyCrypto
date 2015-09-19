//
//  HmacTests.swift
//  EasyCrypto
//
//  Created by Fausto Ristagno on 19/09/15.
//  Copyright © 2015 Fausto Ristagno. All rights reserved.
//

import XCTest
import EasyCrypto

class HmacTests: XCTestCase {
    let key = "EasyCrypto"
    let msg = "SuperSecretString"
    var keyData: NSData!
    var msgData: NSData!
    
    var hmac_md5: ECHmac!
    var hmac_sha1: ECHmac!
    var hmac_sha224: ECHmac!
    var hmac_sha256: ECHmac!
    var hmac_sha384: ECHmac!
    var hmac_sha512: ECHmac!
    
    
    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
        self.keyData = self.key.dataUsingEncoding(NSUTF8StringEncoding)
        self.msgData = self.msg.dataUsingEncoding(NSUTF8StringEncoding)
        
        self.hmac_md5    = ECHmac(key: self.key, content: self.msg, digestAlg: ECHmacDigestAlgorithm.MD5)
        self.hmac_sha1   = ECHmac(key: self.key, content: self.msg, digestAlg: ECHmacDigestAlgorithm.SHA1)
        self.hmac_sha224 = ECHmac(key: self.key, content: self.msg, digestAlg: ECHmacDigestAlgorithm.SHA224)
        self.hmac_sha256 = ECHmac(key: self.key, content: self.msg, digestAlg: ECHmacDigestAlgorithm.SHA256)
        self.hmac_sha384 = ECHmac(key: self.key, content: self.msg, digestAlg: ECHmacDigestAlgorithm.SHA384)
        self.hmac_sha512 = ECHmac(key: self.key, content: self.msg, digestAlg: ECHmacDigestAlgorithm.SHA512)
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }

    func testHmac() {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct results.
        XCTAssertEqual(self.hmac_md5.hexDigest,     "8b909ef32f1363ef7a44568861ca1e34")
        XCTAssertEqual(self.hmac_sha1.hexDigest,    "955f8938cfd99194ea109987471edb36ff4ec746")
        XCTAssertEqual(self.hmac_sha224.hexDigest,  "2f31d9c4af87279aaac36ad0686c28353a8d40b07f74edb8542582d0")
        XCTAssertEqual(self.hmac_sha256.hexDigest,  "dcdf8438b6face10be9735e40caac102fc4e46bd09aa2cb14efa391872c466bf")
        XCTAssertEqual(self.hmac_sha384.hexDigest,  "0caf7558e6f3a0d485b1f756be58c90c3d4c6031a4320c6de838314b3422c1a7f520d7f63cb86e4604d3c5d38e0a5e41")
        XCTAssertEqual(self.hmac_sha512.hexDigest,  "b9c2e0115e73636262eae929d5eda6795d3bd1e620ccfd778bd09357145e416b191e2e061dfb24fa13e8e9cd89e232a71cba4c8fd6ea3dd9fe2c3b62bd1ab579")
    }
    
    /// HMAC-SHA1 is used to generate the authentication signature of the Amazon S3 REST API
    /// - Note: Read: [AWS S3: Signing and Authenticating REST Requests](http://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html)
    func testAwsS3AutheticationKey() {
        let secretAccessKeyId = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        let stringToSign = "GET\n" +
            "\n" + 
            "\n" +
            "Tue, 27 Mar 2007 19:36:42 +0000\n" +
            "/johnsmith/photos/puppy.jpg"
        
        let hmac_aws = ECHmac(key: secretAccessKeyId, content: stringToSign, digestAlg: ECHmacDigestAlgorithm.SHA1)
        let signature = hmac_aws.digest.base64EncodedStringWithOptions(NSDataBase64EncodingOptions(rawValue: 0))
        
        XCTAssertEqual(signature, "bWq2s1WEIj+Ydj0vQ697zp+IXMU=")
    }

}
