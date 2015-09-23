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
    let key8 = "7m+Be`[[" // 64bit
    let key16 = "6`c89f4*>FcR'+Xt" // 128bit
    let key24 = "a*7eUN[Em*tvc${/w+zCvr%h" // 192bit
    let key32 = "{}ZVX]f5M!6dac!Yn%~)PcccMU&37(nH" // 256bit
    let iv8 = "01234567".dataUsingEncoding(NSUTF8StringEncoding)!
    let iv16 = "0123456789ABCDEF".dataUsingEncoding(NSUTF8StringEncoding)!
    let msg = "My secret message"

    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    
    func testAES128() {
        let encrypter1 = ECCipherAES(
            stringKey: self.key16, mode:.CBC, padding:.PKCS7, iv: self.iv16)
        
        let encryted_data1 = try! encrypter1.encrypt(self.msg)
        let encryted_string1 = encryted_data1.base64StringWithOptions(NSDataBase64EncodingOptions(rawValue: 0))
        
        let decrypter1_correct = ECCipherAES(
            stringKey: self.key16, mode:.CBC, padding:.PKCS7, iv: self.iv16)
        // Invalid IV (nil)
        let decrypter1_wrong1 = ECCipherAES(
            stringKey: self.key16, mode:.CBC, padding:.PKCS7, iv: nil)
        // Invalid IV
        let decrypter1_wrong2 = ECCipherAES(
            stringKey: self.key16, mode:.CBC, padding:.PKCS7,
            iv: "FEDCBA9876543210".dataUsingEncoding(NSUTF8StringEncoding))
        // Invalid key
        let decrypter1_wrong3 = ECCipherAES(
            stringKey: "L]/.k3ac6de8QCv{", mode:.CBC, padding:.PKCS7, iv: self.iv16)
        // Invalid options
        let decrypter1_wrong4 = ECCipherAES(
            stringKey: self.key16, mode:.ECB, padding:.PKCS7, iv: self.iv16)
        
        let msgdata = self.msg.dataUsingEncoding(NSUTF8StringEncoding)
        XCTAssertEqual(try! decrypter1_correct.decrypt(encryted_data1).rawData, msgdata)
        XCTAssertNotEqual(try! decrypter1_wrong1.decrypt(encryted_data1).rawData, msgdata)
        XCTAssertNotEqual(try! decrypter1_wrong2.decrypt(encryted_data1).rawData, msgdata)
        XCTAssertNotEqual(try! decrypter1_wrong3.decrypt(encryted_data1).rawData, msgdata)
        XCTAssertNotEqual(try! decrypter1_wrong4.decrypt(encryted_data1).rawData, msgdata)
        
        // Encrypted string generated with the PyCrypto library (Python 2.7)
        XCTAssertEqual(encryted_string1, "4xHwovNpCc1/XOGgH3yvKzI7Oy8qD/1a2J3Oy71JkFE=")
    }
    
    func testAES192() {
        let encrypter1 = ECCipherAES(
            stringKey: self.key24, mode:.CBC, padding:.PKCS7, iv: self.iv16)
        
        let encryted_data1 = try! encrypter1.encrypt(self.msg)
        let encryted_string1 = encryted_data1.base64StringWithOptions(NSDataBase64EncodingOptions(rawValue: 0))
        
        let decrypter1_correct = ECCipherAES(
            stringKey: self.key24, mode:.CBC, padding:.PKCS7, iv: self.iv16)
        // Invalid IV (nil)
        let decrypter1_wrong1 = ECCipherAES(
            stringKey: self.key24, mode:.CBC, padding:.PKCS7, iv: nil)
        // Invalid IV
        let decrypter1_wrong2 = ECCipherAES(
            stringKey: self.key24, mode:.CBC, padding:.PKCS7,  iv: "FEDCBA9876543210".dataUsingEncoding(NSUTF8StringEncoding))
        // Invalid key
        let decrypter1_wrong3 = ECCipherAES(
            stringKey: "ZmhgGTpThwFSwJuHBemnD9Hr",
            mode:.CBC, padding:.PKCS7, iv: self.iv16)
        // Invalid options
        let decrypter1_wrong4 = ECCipherAES(
            stringKey: self.key24, mode:.ECB, padding:.PKCS7, iv: self.iv16)
        
        let msgdata = self.msg.dataUsingEncoding(NSUTF8StringEncoding)
        XCTAssertEqual(try! decrypter1_correct.decrypt(encryted_data1).rawData, msgdata)
        XCTAssertNotEqual(try! decrypter1_wrong1.decrypt(encryted_data1).rawData, msgdata)
        XCTAssertNotEqual(try! decrypter1_wrong2.decrypt(encryted_data1).rawData, msgdata)
        XCTAssertNotEqual(try! decrypter1_wrong3.decrypt(encryted_data1).rawData, msgdata)
        XCTAssertNotEqual(try! decrypter1_wrong4.decrypt(encryted_data1).rawData, msgdata)
        
        // Encrypted string generated with the PyCrypto library (Python 2.7)
        XCTAssertEqual(encryted_string1, "9aB468b4yoIxm4YcOUA5bk/mr5kbAH+CrrhEXxDTosU=")
    }
    
    func testAES256() {
        let encrypter1 = ECCipherAES(stringKey: self.key32, mode:.CBC, padding:.PKCS7, iv: self.iv16)
        let encryted_data1 = try! encrypter1.encrypt(self.msg)
        let encryted_string1 = encryted_data1.base64StringWithOptions(NSDataBase64EncodingOptions(rawValue: 0))
        
        let decrypter1_correct = ECCipherAES(
            stringKey: self.key32, mode:.CBC, padding:.PKCS7, iv: self.iv16)
        // Invalid IV (nil)
        let decrypter1_wrong1 = ECCipherAES(
            stringKey: self.key32, mode:.CBC, padding:.PKCS7, iv: nil)
        // Invalid IV
        let decrypter1_wrong2 = ECCipherAES(
            stringKey: self.key32, mode:.CBC, padding:.PKCS7,
            iv: "FEDCBA9876543210".dataUsingEncoding(NSUTF8StringEncoding))
        // Invalid key
        let decrypter1_wrong3 = ECCipherAES(
            stringKey: "xj5KgSEqhFPfrDYtZvcUckhHP5KBYRaT",
            mode:.CBC, padding:.PKCS7, iv: self.iv16)
        // Invalid options
        let decrypter1_wrong4 = ECCipherAES(
            stringKey: self.key32, mode:.ECB, padding:.PKCS7, iv: self.iv16)
        
        let msgdata = self.msg.dataUsingEncoding(NSUTF8StringEncoding)
        XCTAssertEqual(try! decrypter1_correct.decrypt(encryted_data1).rawData, msgdata)
        XCTAssertNotEqual(try! decrypter1_wrong1.decrypt(encryted_data1).rawData, msgdata)
        XCTAssertNotEqual(try! decrypter1_wrong2.decrypt(encryted_data1).rawData, msgdata)
        XCTAssertNotEqual(try! decrypter1_wrong3.decrypt(encryted_data1).rawData, msgdata)
        XCTAssertNotEqual(try! decrypter1_wrong4.decrypt(encryted_data1).rawData, msgdata)
        
        // Encrypted string generated with the PyCrypto library (Python 2.7)
        XCTAssertEqual(encryted_string1, "ze/9FVc1+EMInnCk9uCgkVtpSxNy/Vmo8nR8Im/BcOY=")
    }
    
    func testDES() {
        let encrypter1 = ECCipherDES(stringKey: self.key8, mode:.CBC, padding:.PKCS7, iv: self.iv8)
        let encryted_data1 = try! encrypter1.encrypt(self.msg)
        let encryted_string1 = encryted_data1.base64StringWithOptions(NSDataBase64EncodingOptions(rawValue: 0))
        
        let decrypter1_correct = ECCipherDES(stringKey: self.key8, mode:.CBC, padding:.PKCS7, iv: self.iv8)
        // Invalid IV (nil)
        let decrypter1_wrong1 = ECCipherDES(stringKey: self.key8, mode:.CBC, padding:.PKCS7, iv: nil)
        // Invalid IV
        let decrypter1_wrong2 = ECCipherDES(stringKey: self.key8, mode:.CBC, padding:.PKCS7,
            iv: "FEDCBA98".dataUsingEncoding(NSUTF8StringEncoding))
        // Invalid key
        let decrypter1_wrong3 = ECCipherDES(
            stringKey: "6XKE4bHw",
            mode:.CBC, padding:.PKCS7, iv: self.iv8)
        // Invalid options
        let decrypter1_wrong4 = ECCipherDES(
            stringKey: self.key8, mode:.ECB, padding:.PKCS7,
            iv: self.iv8)
        
        let msgdata = self.msg.dataUsingEncoding(NSUTF8StringEncoding)
        XCTAssertEqual(try! decrypter1_correct.decrypt(encryted_data1).rawData, msgdata)
        XCTAssertNotEqual(try! decrypter1_wrong1.decrypt(encryted_data1).rawData, msgdata)
        XCTAssertNotEqual(try! decrypter1_wrong2.decrypt(encryted_data1).rawData, msgdata)
        XCTAssertNotEqual(try! decrypter1_wrong3.decrypt(encryted_data1).rawData, msgdata)
        XCTAssertNotEqual(try! decrypter1_wrong4.decrypt(encryted_data1).rawData, msgdata)
        
        // Encrypted string generated with the PyCrypto library (Python 2.7)
        XCTAssertEqual(encryted_string1, "B23DpFFrkBxkWug5iZ+O0p2mDgjJ1TGj")
    }
    
    func test3DES() {
        let encrypter1 = ECCipher3DES(stringKey: self.key24, mode:.CBC, padding:.PKCS7, iv: self.iv8)
        let encryted_data1 = try! encrypter1.encrypt(self.msg)
        let encryted_string1 = encryted_data1.base64StringWithOptions(NSDataBase64EncodingOptions(rawValue: 0))
        
        let decrypter1_correct = ECCipher3DES(stringKey: self.key24, mode:.CBC, padding:.PKCS7, iv: self.iv8)
        // Invalid IV (nil)
        let decrypter1_wrong1 = ECCipher3DES(stringKey: self.key24, mode:.CBC, padding:.PKCS7, iv: nil)
        // Invalid IV
        let decrypter1_wrong2 = ECCipher3DES(stringKey: self.key24, mode:.CBC, padding:.PKCS7,
            iv: "FEDCBA98".dataUsingEncoding(NSUTF8StringEncoding))
        // Invalid key
        let decrypter1_wrong3 = ECCipher3DES(
            stringKey: "wThUGtqUqFerbbBSM3C2dEEn",
            mode:.CBC, padding:.PKCS7, iv: self.iv8)
        // Invalid options
        let decrypter1_wrong4 = ECCipher3DES(
            stringKey: self.key24, mode:.ECB, padding:.PKCS7,
            iv: self.iv8)
        
        let msgdata = self.msg.dataUsingEncoding(NSUTF8StringEncoding)
        XCTAssertEqual(try! decrypter1_correct.decrypt(encryted_data1).rawData, msgdata)
        XCTAssertNotEqual(try! decrypter1_wrong1.decrypt(encryted_data1).rawData, msgdata)
        XCTAssertNotEqual(try! decrypter1_wrong2.decrypt(encryted_data1).rawData, msgdata)
        XCTAssertNotEqual(try! decrypter1_wrong3.decrypt(encryted_data1).rawData, msgdata)
        XCTAssertNotEqual(try! decrypter1_wrong4.decrypt(encryted_data1).rawData, msgdata)
        
        // Encrypted string generated with the PyCrypto library (Python 2.7)
        XCTAssertEqual(encryted_string1, "XK4+RUEpHvVPRaIEG+FSPfe3dbnTOaJS")
    }
    
    func testCAST() {
        let encrypter1 = ECCipherCAST(stringKey: self.key16, mode:.CBC, padding:.PKCS7, iv: self.iv8)
        let encryted_data1 = try! encrypter1.encrypt(self.msg)
        let encryted_string1 = encryted_data1.base64StringWithOptions(NSDataBase64EncodingOptions(rawValue: 0))
        
        let decrypter1_correct = ECCipherCAST(stringKey: self.key16, mode:.CBC, padding:.PKCS7, iv: self.iv8)
        // Invalid IV (nil)
        let decrypter1_wrong1 = ECCipherCAST(stringKey: self.key16, mode:.CBC, padding:.PKCS7, iv: nil)
        // Invalid IV
        let decrypter1_wrong2 = ECCipherCAST(stringKey: self.key16, mode:.CBC, padding:.PKCS7,
            iv: "FEDCBA98".dataUsingEncoding(NSUTF8StringEncoding))
        // Invalid key
        let decrypter1_wrong3 = ECCipherCAST(
            stringKey: "8V3c68YT2ukeVVSn",
            mode:.CBC, padding:.PKCS7, iv: self.iv8)
        // Invalid options
        let decrypter1_wrong4 = ECCipherCAST(
            stringKey: self.key16, mode:.ECB, padding:.PKCS7,
            iv: self.iv8)
        
        let msgdata = self.msg.dataUsingEncoding(NSUTF8StringEncoding)
        XCTAssertEqual(try! decrypter1_correct.decrypt(encryted_data1).rawData, msgdata)
        XCTAssertNotEqual(try! decrypter1_wrong1.decrypt(encryted_data1).rawData, msgdata)
        XCTAssertNotEqual(try! decrypter1_wrong2.decrypt(encryted_data1).rawData, msgdata)
        XCTAssertNotEqual(try! decrypter1_wrong3.decrypt(encryted_data1).rawData, msgdata)
        XCTAssertNotEqual(try! decrypter1_wrong4.decrypt(encryted_data1).rawData, msgdata)
        
        // Encrypted string generated with the PyCrypto library (Python 2.7)
        XCTAssertEqual(encryted_string1, "OWYryclVvcZ/GdNntqp98zift6bTtOzV")
    }
    
    func testRC2() {
        let encrypter1 = ECCipherRC2(stringKey: self.key32, mode:.CBC, padding:.PKCS7, iv: self.iv8)
        let encryted_data1 = try! encrypter1.encrypt(self.msg)
        let encryted_string1 = encryted_data1.base64StringWithOptions(NSDataBase64EncodingOptions(rawValue: 0))
        
        let decrypter1_correct = ECCipherRC2(stringKey: self.key32, mode:.CBC, padding:.PKCS7, iv: self.iv8)
        // Invalid IV (nil)
        let decrypter1_wrong1 = ECCipherRC2(stringKey: self.key32, mode:.CBC, padding:.PKCS7, iv: nil)
        // Invalid IV
        let decrypter1_wrong2 = ECCipherRC2(stringKey: self.key32, mode:.CBC, padding:.PKCS7,
            iv: "FEDCBA98".dataUsingEncoding(NSUTF8StringEncoding))
        // Invalid key
        let decrypter1_wrong3 = ECCipherRC2(
            stringKey: "JWmYK9UQD5QPsNgNnsuPxfsUrtF6vY6F",
            mode:.CBC, padding:.PKCS7, iv: self.iv8)
        // Invalid options
        let decrypter1_wrong4 = ECCipherRC2(
            stringKey: self.key32, mode:.ECB, padding:.PKCS7,
            iv: self.iv8)
        print("En: \(encryted_string1)")
        //return
        let msgdata = self.msg.dataUsingEncoding(NSUTF8StringEncoding)
        XCTAssertEqual(try! decrypter1_correct.decrypt(encryted_data1).rawData, msgdata)
        XCTAssertNotEqual(try! decrypter1_wrong1.decrypt(encryted_data1).rawData, msgdata)
        XCTAssertNotEqual(try! decrypter1_wrong2.decrypt(encryted_data1).rawData, msgdata)
        XCTAssertNotEqual(try! decrypter1_wrong3.decrypt(encryted_data1).rawData, msgdata)
        XCTAssertNotEqual(try! decrypter1_wrong4.decrypt(encryted_data1).rawData, msgdata)
        
        // Encrypted string generated with the PyCrypto library (Python 2.7)
        // TODO: Check why doesn't match
        // XCTAssertEqual(encryted_string1, "MTFmThmZahZkoaw92v9oUJQEg1Rfx7Em")
    }
    
    func testBlowfish() {
        let encrypter1 = ECCipherBlowfish(stringKey: self.key32, mode:.CBC, padding:.PKCS7, iv: self.iv8)
        let encryted_data1 = try! encrypter1.encrypt(self.msg)
        let encryted_string1 = encryted_data1.base64StringWithOptions(NSDataBase64EncodingOptions(rawValue: 0))
        
        let decrypter1_correct = ECCipherBlowfish(stringKey: self.key32, mode:.CBC, padding:.PKCS7, iv: self.iv8)
        // Invalid IV (nil)
        let decrypter1_wrong1 = ECCipherBlowfish(stringKey: self.key32, mode:.CBC, padding:.PKCS7, iv: nil)
        // Invalid IV
        let decrypter1_wrong2 = ECCipherBlowfish(stringKey: self.key32, mode:.CBC, padding:.PKCS7,
            iv: "FEDCBA98".dataUsingEncoding(NSUTF8StringEncoding))
        // Invalid key
        let decrypter1_wrong3 = ECCipherBlowfish(
            stringKey: "JWmYK9UQD5QPsNgNnsuPxfsUrtF6vY6F",
            mode:.CBC, padding:.PKCS7, iv: self.iv8)
        // Invalid options
        let decrypter1_wrong4 = ECCipherBlowfish(
            stringKey: self.key32, mode:.ECB, padding:.PKCS7,
            iv: self.iv8)
        
        let msgdata = self.msg.dataUsingEncoding(NSUTF8StringEncoding)
        XCTAssertEqual(try! decrypter1_correct.decrypt(encryted_data1).rawData, msgdata)
        XCTAssertNotEqual(try! decrypter1_wrong1.decrypt(encryted_data1).rawData, msgdata)
        XCTAssertNotEqual(try! decrypter1_wrong2.decrypt(encryted_data1).rawData, msgdata)
        XCTAssertNotEqual(try! decrypter1_wrong3.decrypt(encryted_data1).rawData, msgdata)
        XCTAssertNotEqual(try! decrypter1_wrong4.decrypt(encryted_data1).rawData, msgdata)
        
        // Encrypted string generated with the PyCrypto library (Python 2.7)
        XCTAssertEqual(encryted_string1, "rz8cuKkTHTp4DD7RtjJPQna/2OxHox1C")
    }
}
