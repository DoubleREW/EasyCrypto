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
        let c = ECCipherAES(stringKey: "ciao", option: .CBCModePKCS7Padding, keySize: .SizeAES256, iv: iv)
        let d = ECCipherAES(stringKey: "ciao", option: .CBCModePKCS7Padding, keySize: .SizeAES256, iv: iv)
        let e = try! c.encrypt(m)
        
        XCTAssertEqual(try! d.decrypt(e).rawData, m.dataUsingEncoding(NSUTF8StringEncoding))
    }
    
    func testExample2() {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct results.
        let key = "0123456789abcdef"
        let keySize = Int(ECCipherKeySize.SizeAES128.rawValue)
        let keyData = NSMutableData(data: key.dataUsingEncoding(NSUTF8StringEncoding)!)
        
        for _ in keyData.length..<keySize {
            keyData.appendBytes([0x00], length: 1)
        }
        
        let msg = "0123456789abcde"
        let blockSize = Int(ECCipherBlockSize.SizeAES128.rawValue)
        // let msgData = NSMutableData(data: msg.dataUsingEncoding(NSUTF8StringEncoding)!)
        var testArray = [UInt8]()
        //           0     1     2     3     4     5     6     7     8     9     a     b     c     d
        testArray = [0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66]
        let msgData = NSData(
            bytes: testArray,
            length: 16)
        
        /*
        for _ in msgData.length..<blockSize {
            msgData.appendBytes([0x00], length: 1)
        }
        */
        
        // let iv = "0123456789ABCDEF".dataUsingEncoding(NSUTF8StringEncoding)
        let c = ECCipherAES(dataKey: keyData, option: .ECBModePKCS7Padding, keySize: .SizeAES128, iv: nil)
        let e = try! c.encryptData(msgData)
        
        
        print("\(msgData.base64EncodedStringWithOptions(NSDataBase64EncodingOptions.Encoding76CharacterLineLength))")
        print("\(e.base64StringWithOptions(NSDataBase64EncodingOptions.Encoding76CharacterLineLength))")
        print("\(try! c.decrypt(e).base64StringWithOptions(NSDataBase64EncodingOptions.Encoding76CharacterLineLength))")
    }

    func testPerformanceExample() {
        // This is an example of a performance test case.
        self.measureBlock {
            // Put the code you want to measure the time of here.
        }
    }

}
