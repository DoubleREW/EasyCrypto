//
//  CipherTests.swift
//  EasyCrypto
//
//  Created by Fausto Ristagno on 16/09/15.
//  Copyright © 2015 Fausto Ristagno. All rights reserved.
//

import XCTest
import EasyCrypto

class CipherTests: XCTestCase {

    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }

    func testExample() {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct results.
        let m = "prova prova"
        let iv = "0123456789ABCDEF".dataUsingEncoding(NSUTF8StringEncoding)
        let c = ECCipherAES(stringKey: "ciao", option: .PKCS7Padding, keySize: .SizeAES256, iv: iv)
        let d = ECCipherAES(stringKey: "ciao", option: .PKCS7Padding, keySize: .SizeAES256, iv: iv)
        let e = try! c.encrypt(m)
        
        XCTAssertEqual(try! d.decrypt(e).rawData, m.dataUsingEncoding(NSUTF8StringEncoding))
    }

    func testPerformanceExample() {
        // This is an example of a performance test case.
        self.measureBlock {
            // Put the code you want to measure the time of here.
        }
    }

}
