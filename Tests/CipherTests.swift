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
    let key7 = "76y_A(_" // 56bit
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
            stringKey: self.key16, option: .CBCModePKCS7Padding,
            keySize: .SizeAES128, iv: self.iv16)
        
        let encryted_data1 = try! encrypter1.encrypt(self.msg)
        let encryted_string1 = encryted_data1.base64StringWithOptions(NSDataBase64EncodingOptions(rawValue: 0))
        
        let decrypter1_correct = ECCipherAES(
            stringKey: self.key16, option: .CBCModePKCS7Padding,
            keySize: .SizeAES128, iv: self.iv16)
        // Invalid IV (nil)
        let decrypter1_wrong1 = ECCipherAES(
            stringKey: self.key16, option: .CBCModePKCS7Padding,
            keySize: .SizeAES128, iv: nil)
        // Invalid IV
        let decrypter1_wrong2 = ECCipherAES(
            stringKey: self.key16, option: .CBCModePKCS7Padding,
            keySize: .SizeAES128, iv: "FEDCBA9876543210".dataUsingEncoding(NSUTF8StringEncoding))
        // Invalid key
        let decrypter1_wrong3 = ECCipherAES(
            stringKey: "Invalid key", option: .CBCModePKCS7Padding,
            keySize: .SizeAES128, iv: self.iv16)
        // Invalid options
        let decrypter1_wrong4 = ECCipherAES(
            stringKey: self.key16, option: .ECBModePKCS7Padding,
            keySize: .SizeAES128, iv: self.iv16)
        
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
            stringKey: self.key24, option: .CBCModePKCS7Padding,
            keySize: .SizeAES192, iv: self.iv16)
        
        let encryted_data1 = try! encrypter1.encrypt(self.msg)
        let encryted_string1 = encryted_data1.base64StringWithOptions(NSDataBase64EncodingOptions(rawValue: 0))
        
        let decrypter1_correct = ECCipherAES(
            stringKey: self.key24, option: .CBCModePKCS7Padding,
            keySize: .SizeAES192, iv: self.iv16)
        // Invalid IV (nil)
        let decrypter1_wrong1 = ECCipherAES(
            stringKey: self.key24, option: .CBCModePKCS7Padding,
            keySize: .SizeAES192, iv: nil)
        // Invalid IV
        let decrypter1_wrong2 = ECCipherAES(
            stringKey: self.key24, option: .CBCModePKCS7Padding,
            keySize: .SizeAES192, iv: "FEDCBA9876543210".dataUsingEncoding(NSUTF8StringEncoding))
        // Invalid key
        let decrypter1_wrong3 = ECCipherAES(
            stringKey: "Invalid key", option: .CBCModePKCS7Padding,
            keySize: .SizeAES192, iv: self.iv16)
        // Invalid options
        let decrypter1_wrong4 = ECCipherAES(
            stringKey: self.key24, option: .ECBModePKCS7Padding,
            keySize: .SizeAES192, iv: self.iv16)
        
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
        let encrypter1 = ECCipherAES(stringKey: self.key32, option: .CBCModePKCS7Padding, keySize: .SizeAES256, iv: self.iv16)
        let encryted_data1 = try! encrypter1.encrypt(self.msg)
        let encryted_string1 = encryted_data1.base64StringWithOptions(NSDataBase64EncodingOptions(rawValue: 0))
        
        let decrypter1_correct = ECCipherAES(
            stringKey: self.key32, option: .CBCModePKCS7Padding,
            keySize: .SizeAES256, iv: self.iv16)
        // Invalid IV (nil)
        let decrypter1_wrong1 = ECCipherAES(
            stringKey: self.key32, option: .CBCModePKCS7Padding,
            keySize: .SizeAES256, iv: nil)
        // Invalid IV
        let decrypter1_wrong2 = ECCipherAES(
            stringKey: self.key32, option: .CBCModePKCS7Padding,
            keySize: .SizeAES256, iv: "FEDCBA9876543210".dataUsingEncoding(NSUTF8StringEncoding))
        // Invalid key
        let decrypter1_wrong3 = ECCipherAES(
            stringKey: "Invalid key", option: .CBCModePKCS7Padding,
            keySize: .SizeAES256, iv: self.iv16)
        // Invalid options
        let decrypter1_wrong4 = ECCipherAES(
            stringKey: self.key32, option: .ECBModePKCS7Padding,
            keySize: .SizeAES256, iv: self.iv16)
        
        let msgdata = self.msg.dataUsingEncoding(NSUTF8StringEncoding)
        XCTAssertEqual(try! decrypter1_correct.decrypt(encryted_data1).rawData, msgdata)
        XCTAssertNotEqual(try! decrypter1_wrong1.decrypt(encryted_data1).rawData, msgdata)
        XCTAssertNotEqual(try! decrypter1_wrong2.decrypt(encryted_data1).rawData, msgdata)
        XCTAssertNotEqual(try! decrypter1_wrong3.decrypt(encryted_data1).rawData, msgdata)
        XCTAssertNotEqual(try! decrypter1_wrong4.decrypt(encryted_data1).rawData, msgdata)
        
        // Encrypted string generated with the PyCrypto library (Python 2.7)
        XCTAssertEqual(encryted_string1, "ze/9FVc1+EMInnCk9uCgkVtpSxNy/Vmo8nR8Im/BcOY=")
    }
    /*
    func testDES() {
        let encrypter1 = ECCipherDES(stringKey: self.key8, option: .CBCModePKCS7Padding, keySize: .SizeAES256, iv: self.iv16)
        let encryted_data1 = try! encrypter1.encrypt(self.msg)
        let encryted_string1 = encryted_data1.base64StringWithOptions(NSDataBase64EncodingOptions(rawValue: 0))
        
        let decrypter1_correct = ECCipherAES(
            stringKey: self.key32, option: .CBCModePKCS7Padding,
            keySize: .SizeAES256, iv: self.iv16)
        // Invalid IV (nil)
        let decrypter1_wrong1 = ECCipherAES(
            stringKey: self.key32, option: .CBCModePKCS7Padding,
            keySize: .SizeAES256, iv: nil)
        // Invalid IV
        let decrypter1_wrong2 = ECCipherAES(
            stringKey: self.key32, option: .CBCModePKCS7Padding,
            keySize: .SizeAES256, iv: "FEDCBA9876543210".dataUsingEncoding(NSUTF8StringEncoding))
        // Invalid key
        let decrypter1_wrong3 = ECCipherAES(
            stringKey: "Invalid key", option: .CBCModePKCS7Padding,
            keySize: .SizeAES256, iv: self.iv16)
        // Invalid options
        let decrypter1_wrong4 = ECCipherAES(
            stringKey: self.key32, option: .ECBModePKCS7Padding,
            keySize: .SizeAES256, iv: self.iv16)
        
        let msgdata = self.msg.dataUsingEncoding(NSUTF8StringEncoding)
        XCTAssertEqual(try! decrypter1_correct.decrypt(encryted_data1).rawData, msgdata)
        XCTAssertNotEqual(try! decrypter1_wrong1.decrypt(encryted_data1).rawData, msgdata)
        XCTAssertNotEqual(try! decrypter1_wrong2.decrypt(encryted_data1).rawData, msgdata)
        XCTAssertNotEqual(try! decrypter1_wrong3.decrypt(encryted_data1).rawData, msgdata)
        XCTAssertNotEqual(try! decrypter1_wrong4.decrypt(encryted_data1).rawData, msgdata)
        
        // Encrypted string generated with the PyCrypto library (Python 2.7)
        XCTAssertEqual(encryted_string1, "ze/9FVc1+EMInnCk9uCgkVtpSxNy/Vmo8nR8Im/BcOY=")
    }
    */
}
