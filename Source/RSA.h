//
//  RSA.h
//  CryptoTest
//
//  Created by Fausto Ristagno on 14/09/15.
//  Copyright © 2015 Fausto Ristagno. All rights reserved.
//

#import <Foundation/Foundation.h>

extern NSString *const _Nonnull RSAErrorDomain;

@class RSAKey, RSAKeyPair;

@interface RSA : NSObject

+ (nullable RSAKeyPair *)generateKeyPairWithSize:(NSUInteger)numbits error:(out NSError * _Nullable * _Nullable)error;
+ (nullable RSAKey *)importKey:(nonnull NSString *)keyPath passphrase:(nullable NSString *)passphrase error:(out NSError * _Nullable * _Nullable)error;

@end
