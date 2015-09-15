//
//  RSAKey.h
//  CryptoTest
//
//  Created by Fausto Ristagno on 14/09/15.
//  Copyright © 2015 Fausto Ristagno. All rights reserved.
//

#import <Foundation/Foundation.h>

extern NSString *const _Nonnull RSAKeyErrorDomain;
extern NSInteger RSAKeyVerificationFailedErrorCode;

typedef NS_ENUM(NSUInteger, RSADigestType) {
    RSADigestTypeNone = 0,
    RSADigestTypeMD5,
    RSADigestTypeSHA1,
    RSADigestTypeSHA224,
    RSADigestTypeSHA256,
    RSADigestTypeSHA384,
    RSADigestTypeSHA512,
};

typedef NS_ENUM(NSUInteger, RSAExportFormat) {
    RSAExportFormatPEM = 0
};

@class RSASignature;

@interface RSAKey : NSObject

- (nullable RSASignature *)sign:(nonnull NSData *)data digestType:(RSADigestType)digestTypeRaw error:(out NSError * _Nullable * _Nullable)error;
- (BOOL)verify:(nonnull NSData *)data signature:(nonnull RSASignature *)signature digestType:(RSADigestType)digestTypeRaw error:(out NSError * _Nullable * _Nullable)error;

- (nullable NSData *)exportKey:(RSAExportFormat)format error:(out NSError * _Nullable * _Nullable)error;

@end
