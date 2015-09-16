//
//  ECDigestExtensions.swift
//  EasyCrypto
//
//  Created by Fausto Ristagno on 16/09/15.
//  Copyright © 2015 Fausto Ristagno. All rights reserved.
//

public extension String {
    func md2() -> ECHashMD2 {
        return (self as NSString).md2()
    }
    
    func md4() -> ECHashMD4 {
        return (self as NSString).md4()
    }
    
    func md5() -> ECHashMD5 {
        return (self as NSString).md5()
    }
    
    func sha1() -> ECHashSHA1 {
        return (self as NSString).sha1()
    }
    
    func sha224() -> ECHashSHA224 {
        return (self as NSString).sha224()
    }
    
    func sha256() -> ECHashSHA256 {
        return (self as NSString).sha256()
    }
    
    func sha384() -> ECHashSHA384 {
        return (self as NSString).sha384()
    }
    
    func sha512() -> ECHashSHA512 {
        return (self as NSString).sha512()
    }
}
