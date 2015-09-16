//
//  ECDigestExtensions.swift
//  EasyCrypto
//
//  Created by Fausto Ristagno on 16/09/15.
//  Copyright © 2015 Fausto Ristagno. All rights reserved.
//

public extension String {
    func md2() -> ECMd2 {
        return (self as NSString).md2()
    }
    
    func md4() -> ECMd4 {
        return (self as NSString).md4()
    }
    
    func md5() -> ECMd5 {
        return (self as NSString).md5()
    }
    
    func sha1() -> ECSha1 {
        return (self as NSString).sha1()
    }
    
    func sha224() -> ECSha224 {
        return (self as NSString).sha224()
    }
    
    func sha256() -> ECSha256 {
        return (self as NSString).sha256()
    }
    
    func sha384() -> ECSha384 {
        return (self as NSString).sha384()
    }
    
    func sha512() -> ECSha512 {
        return (self as NSString).sha512()
    }
}
