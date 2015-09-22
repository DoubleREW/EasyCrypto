//
//  ECHmac.m
//  EasyCrypto
//
//  Created by Fausto Ristagno on 19/09/15.
//  Copyright © 2015 Fausto Ristagno. All rights reserved.
//

#import <CommonCrypto/CommonHMAC.h>
#import "ECHmac.h"
#import "ECBaseHash+Private.h"

CCHmacAlgorithm CCHmacAlgFromDigestAlg(ECHmacDigestAlgorithm algo)
{
    switch (algo) {
        case ECHmacDigestAlgorithmMD5:
            return kCCHmacAlgMD5;
        case ECHmacDigestAlgorithmSHA1:
            return kCCHmacAlgSHA1;
        case ECHmacDigestAlgorithmSHA224:
            return kCCHmacAlgSHA224;
        case ECHmacDigestAlgorithmSHA256:
            return kCCHmacAlgSHA256;
        case ECHmacDigestAlgorithmSHA384:
            return kCCHmacAlgSHA384;
        case ECHmacDigestAlgorithmSHA512:
            return kCCHmacAlgSHA512;
            
        default:
            fprintf(stderr, "Invalid digest algorithm (%ld)", algo);
            assert(false);
    }
}


@interface ECHmac ()

@property (nonatomic, strong) NSData *key;
@property (nonatomic, assign) ECHmacDigestAlgorithm digestAlgorithm;

@end

@implementation ECHmac

- (nonnull instancetype)initWithDataKey:(nonnull NSData *)key content:(nonnull NSData *)content digestAlg:(ECHmacDigestAlgorithm)digestmod
{
    NSAssert(key != nil, @"Key must not be nil.");
    NSAssert(content != nil, @"Content must not be nil.");
    
    self = [super init];
    if (self) {
        self.key = key;
        self.digestAlgorithm = digestmod;
        
        [self updateWithData:content];
    }
    
    return self;
}

- (nonnull instancetype)initWithKey:(nonnull NSString *)key content:(nonnull NSString *)content digestAlg:(ECHmacDigestAlgorithm)digestmod
{
    return [self initWithDataKey:[key dataUsingEncoding:NSUTF8StringEncoding]
                         content:[content dataUsingEncoding:NSUTF8StringEncoding]
                       digestAlg:digestmod];
}

- (NSInteger)digestLength
{
    switch (self.digestAlgorithm) {
        case ECHmacDigestAlgorithmMD5:
            return CC_MD5_DIGEST_LENGTH;
        case ECHmacDigestAlgorithmSHA1:
            return CC_SHA1_DIGEST_LENGTH;
        case ECHmacDigestAlgorithmSHA224:
            return CC_SHA224_DIGEST_LENGTH;
        case ECHmacDigestAlgorithmSHA256:
            return CC_SHA256_DIGEST_LENGTH;
        case ECHmacDigestAlgorithmSHA384:
            return CC_SHA384_DIGEST_LENGTH;
        case ECHmacDigestAlgorithmSHA512:
            return CC_SHA512_DIGEST_LENGTH;
        
        default:
            return 0;
    }
}

- (NSData *)_calculateDigest:(const void *)cData len:(CC_LONG)dataLen;
{
    const void *cKey  = [self.key bytes];
    size_t keyLen = [self.key length];
    unsigned char cHMAC[self.digestLength];
    
    CCHmac(CCHmacAlgFromDigestAlg(self.digestAlgorithm), cKey, keyLen, cData, dataLen, cHMAC);
    
    
    return [[NSData alloc] initWithBytes:cHMAC length:sizeof(cHMAC)];
}

@end
