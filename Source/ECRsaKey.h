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

typedef NS_ENUM(NSUInteger, ECRsaDigestType) {
    ECRsaDigestTypeNone = 0,
    ECRsaDigestTypeMD5,
    ECRsaDigestTypeSHA1,
    ECRsaDigestTypeSHA224,
    ECRsaDigestTypeSHA256,
    ECRsaDigestTypeSHA384,
    ECRsaDigestTypeSHA512,
};

typedef NS_ENUM(NSUInteger, ECRsaExportFormat) {
    ECRsaExportFormatPEM = 0
};

@class ECRsaSignature;

@interface ECRsaKey : NSObject

- (nullable ECRsaSignature *)sign:(nonnull NSData *)data digestType:(ECRsaDigestType)digestTypeRaw error:(out NSError * _Nullable * _Nullable)error;
- (BOOL)verify:(nonnull NSData *)data signature:(nonnull ECRsaSignature *)signature digestType:(ECRsaDigestType)digestTypeRaw error:(out NSError * _Nullable * _Nullable)error;

- (nullable NSData *)exportKey:(ECRsaExportFormat)format error:(out NSError * _Nullable * _Nullable)error;

@end
