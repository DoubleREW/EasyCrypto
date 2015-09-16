//
//  RSA.h
//  CryptoTest
//
//  Created by Fausto Ristagno on 14/09/15.
//  Copyright © 2015 Fausto Ristagno. All rights reserved.
//

#import <Foundation/Foundation.h>

extern NSString *const _Nonnull ECRsaErrorDomain;

@class ECRsaKey, ECRsaKeyPair;

@interface ECRsa : NSObject

+ (nullable ECRsaKeyPair *)generateKeyPairWithSize:(NSUInteger)numbits error:(out NSError * _Nullable * _Nullable)error;
+ (nullable ECRsaKey *)importKey:(nonnull NSString *)keyPath passphrase:(nullable NSString *)passphrase error:(out NSError * _Nullable * _Nullable)error;

@end
