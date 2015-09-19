//
//  ECBaseHash.m
//  EasyCrypto
//
//  Created by Fausto Ristagno on 19/09/15.
//  Copyright © 2015 Fausto Ristagno. All rights reserved.
//

#import "ECBaseHash.h"
#import "ECBaseHash+Private.h"


@implementation ECBaseHash

- (void)updateWithData:(nonnull NSData *)data
{
    NSAssert(data != nil, @"The input parameter must not be nil.");
    
    self.inputData = data;
    const void *databytes = [data bytes];
    CC_LONG datalen = (CC_LONG)[data length];
    
    self.digest = [self _calculateDigest:databytes len:datalen];
    self.hexDigest = [self _calculateHexDigest:self.digest];
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
