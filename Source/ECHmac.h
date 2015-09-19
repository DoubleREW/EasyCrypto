//
//  ECHmac.h
//  EasyCrypto
//
//  Created by Fausto Ristagno on 19/09/15.
//  Copyright © 2015 Fausto Ristagno. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "ECBaseHash.h"


typedef NS_ENUM(NSUInteger, ECHmacDigestAlgorithm) {
    ECHmacDigestAlgorithmMD5,
    ECHmacDigestAlgorithmSHA1,
    ECHmacDigestAlgorithmSHA224,
    ECHmacDigestAlgorithmSHA256,
    ECHmacDigestAlgorithmSHA384,
    ECHmacDigestAlgorithmSHA512
};

@interface ECHmac : ECBaseHash

@property (nonatomic, readonly, nonnull) NSData *key;
@property (nonatomic, readonly) ECHmacDigestAlgorithm digestAlgorithm;

- (nonnull instancetype)initWithKey:(nonnull NSString *)key content:(nonnull NSString *)content digestAlg:(ECHmacDigestAlgorithm)digestalg;
- (nonnull instancetype)initWithDataKey:(nonnull NSData *)key content:(nonnull NSData *)content digestAlg:(ECHmacDigestAlgorithm)digestalg;

@end
