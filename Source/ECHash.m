//
//  ECDigestObject.m
//  EasyCrypto
//
//  Created by Fausto Ristagno on 16/09/15.
//  Copyright © 2015 Fausto Ristagno. All rights reserved.
//

#import "ECHash.h"
#import "ECBaseHash+Private.h"


@implementation ECHash

- (nonnull instancetype)initWithData:(nonnull NSData *)data
{
    NSAssert(data != nil, @"The input parameter must not be nil.");
    
    self = [super init];
    if (self) {
        [self updateWithData:data];
    }
    
    return self;
}

- (nonnull instancetype)initWithString:(nonnull NSString *)str
{
    NSData *data = [str dataUsingEncoding:NSUTF8StringEncoding];
    return [self initWithData:data];
}

@end


// MARK: Implementations
@implementation ECHashMD2

- (NSUInteger)digestLength
{
    return CC_MD2_DIGEST_LENGTH;
}

- (NSData *)_calculateDigest:(const void *)data len:(CC_LONG)len;
{
    uint8_t md[CC_MD2_DIGEST_LENGTH];
    CC_MD2(data, len, md);
    
    return [NSData dataWithBytes:md length:CC_MD2_DIGEST_LENGTH];
}

@end

@implementation ECHashMD4

- (NSUInteger)digestLength
{
    return CC_MD4_DIGEST_LENGTH;
}

- (NSData *)_calculateDigest:(const void *)data len:(CC_LONG)len;
{
    uint8_t md[CC_MD4_DIGEST_LENGTH];
    CC_MD4(data, len, md);
    
    return [NSData dataWithBytes:md length:CC_MD4_DIGEST_LENGTH];
}

@end

@implementation ECHashMD5

- (NSUInteger)digestLength
{
    return CC_MD5_DIGEST_LENGTH;
}

- (NSData *)_calculateDigest:(const void *)data len:(CC_LONG)len;
{
    uint8_t md[CC_MD5_DIGEST_LENGTH];
    CC_MD5(data, len, md);
    
    return [NSData dataWithBytes:md length:CC_MD5_DIGEST_LENGTH];
}

@end

@implementation ECHashSHA1

- (NSUInteger)digestLength
{
    return CC_SHA1_DIGEST_LENGTH;
}

- (NSData *)_calculateDigest:(const void *)data len:(CC_LONG)len;
{
    uint8_t md[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1(data, len, md);
    
    return [NSData dataWithBytes:md length:CC_SHA1_DIGEST_LENGTH];
}

@end

@implementation ECHashSHA224

- (NSUInteger)digestLength
{
    return CC_SHA224_DIGEST_LENGTH;
}

- (NSData *)_calculateDigest:(const void *)data len:(CC_LONG)len;
{
    uint8_t md[CC_SHA224_DIGEST_LENGTH];
    CC_SHA224(data, len, md);
    
    return [NSData dataWithBytes:md length:CC_SHA224_DIGEST_LENGTH];
}

@end

@implementation ECHashSHA256

- (NSUInteger)digestLength
{
    return CC_SHA256_DIGEST_LENGTH;
}

- (NSData *)_calculateDigest:(const void *)data len:(CC_LONG)len;
{
    uint8_t md[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data, len, md);
    
    return [NSData dataWithBytes:md length:CC_SHA256_DIGEST_LENGTH];
}

@end

@implementation ECHashSHA384

- (NSUInteger)digestLength
{
    return CC_SHA384_DIGEST_LENGTH;
}

- (NSData *)_calculateDigest:(const void *)data len:(CC_LONG)len;
{
    uint8_t md[CC_SHA384_DIGEST_LENGTH];
    CC_SHA384(data, len, md);
    
    return [NSData dataWithBytes:md length:CC_SHA384_DIGEST_LENGTH];
}

@end

@implementation ECHashSHA512

- (NSUInteger)digestLength
{
    return CC_SHA512_DIGEST_LENGTH;
}

- (NSData *)_calculateDigest:(const void *)data len:(CC_LONG)len;
{
    uint8_t md[CC_SHA512_DIGEST_LENGTH];
    CC_SHA512(data, len, md);
    
    return [NSData dataWithBytes:md length:CC_SHA512_DIGEST_LENGTH];
}

@end
