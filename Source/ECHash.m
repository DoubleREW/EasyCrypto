//
//  ECDigestObject.m
//  EasyCrypto
//
//  Created by Fausto Ristagno on 16/09/15.
//  Copyright © 2015 Fausto Ristagno. All rights reserved.
//

#import "ECDigestObject.h"
#import "ECDigestObject+Private.h"

@interface ECDigestObject ()

@property (nonatomic, strong) NSData *inputData;

@end

@implementation ECDigestObject

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

- (void)updateWithData:(nonnull NSData *)data
{
    NSAssert(data != nil, @"The input parameter must not be nil.");
    
    self.inputData = data;
    const void *databytes = [data bytes];
    CC_LONG datalen = (CC_LONG)[data length];
    
    _digest = [self _calculateDigest:databytes len:datalen];
    _hexDigest = [self _calculateHexDigest:_digest];
}

- (void)updateWithString:(nonnull NSString *)str
{
    NSData *data = [str dataUsingEncoding:NSUTF8StringEncoding];
    [self updateWithData:data];
}

- (void)update:(nonnull NSString *)str
{
    [self updateWithString:str];
}

- (NSData *)_calculateDigest:(const void *)data len:(CC_LONG)len
{
    [NSException raise:NSInternalInconsistencyException
                format:@"You must override %@ in a subclass", NSStringFromSelector(_cmd)];
    
    return nil;
}

- (NSString *)_calculateHexDigest:(NSData *)data
{
    NSMutableString *hex = [NSMutableString stringWithCapacity:[data length]];
    
    [data enumerateByteRangesUsingBlock:^(const void * _Nonnull bytes, NSRange byteRange, BOOL * _Nonnull stop) {
        for (NSUInteger i = 0; i < byteRange.length; ++i) {
            [hex appendFormat:@"%02x", ((uint8_t*)bytes)[i]];
        }
    }];
    
    return hex;
}

@end


// MARK: Implementations
@implementation ECMd2

- (NSUInteger)digestLength
{
    return CC_MD2_DIGEST_LENGTH * 8;
}

- (NSData *)_calculateDigest:(const void *)data len:(CC_LONG)len;
{
    uint8_t md[CC_MD2_DIGEST_LENGTH];
    CC_MD2(data, len, md);
    
    return [NSData dataWithBytes:md length:CC_MD2_DIGEST_LENGTH];
}

@end

@implementation ECMd4

- (NSUInteger)digestLength
{
    return CC_MD4_DIGEST_LENGTH * 8;
}

- (NSData *)_calculateDigest:(const void *)data len:(CC_LONG)len;
{
    uint8_t md[CC_MD4_DIGEST_LENGTH];
    CC_MD4(data, len, md);
    
    return [NSData dataWithBytes:md length:CC_MD4_DIGEST_LENGTH];
}

@end

@implementation ECMd5

- (NSUInteger)digestLength
{
    return CC_MD5_DIGEST_LENGTH * 8;
}

- (NSData *)_calculateDigest:(const void *)data len:(CC_LONG)len;
{
    uint8_t md[CC_MD5_DIGEST_LENGTH];
    CC_MD5(data, len, md);
    
    return [NSData dataWithBytes:md length:CC_MD5_DIGEST_LENGTH];
}

@end

@implementation ECSha1

- (NSUInteger)digestLength
{
    return CC_SHA1_DIGEST_LENGTH * 8;
}

- (NSData *)_calculateDigest:(const void *)data len:(CC_LONG)len;
{
    uint8_t md[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1(data, len, md);
    
    return [NSData dataWithBytes:md length:CC_SHA1_DIGEST_LENGTH];
}

@end

@implementation ECSha224

- (NSUInteger)digestLength
{
    return CC_SHA224_DIGEST_LENGTH * 8;
}

- (NSData *)_calculateDigest:(const void *)data len:(CC_LONG)len;
{
    uint8_t md[CC_SHA224_DIGEST_LENGTH];
    CC_SHA224(data, len, md);
    
    return [NSData dataWithBytes:md length:CC_SHA224_DIGEST_LENGTH];
}

@end

@implementation ECSha256

- (NSUInteger)digestLength
{
    return CC_SHA256_DIGEST_LENGTH * 8;
}

- (NSData *)_calculateDigest:(const void *)data len:(CC_LONG)len;
{
    uint8_t md[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data, len, md);
    
    return [NSData dataWithBytes:md length:CC_SHA256_DIGEST_LENGTH];
}

@end

@implementation ECSha384

- (NSUInteger)digestLength
{
    return CC_SHA384_DIGEST_LENGTH * 8;
}

- (NSData *)_calculateDigest:(const void *)data len:(CC_LONG)len;
{
    uint8_t md[CC_SHA384_DIGEST_LENGTH];
    CC_SHA384(data, len, md);
    
    return [NSData dataWithBytes:md length:CC_SHA384_DIGEST_LENGTH];
}

@end

@implementation ECSha512

- (NSUInteger)digestLength
{
    return CC_SHA512_DIGEST_LENGTH * 8;
}

- (NSData *)_calculateDigest:(const void *)data len:(CC_LONG)len;
{
    uint8_t md[CC_SHA512_DIGEST_LENGTH];
    CC_SHA512(data, len, md);
    
    return [NSData dataWithBytes:md length:CC_SHA512_DIGEST_LENGTH];
}

@end
