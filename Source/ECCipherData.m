//
//  ECCipherPlainData.m
//  EasyCrypto
//
//  Created by Fausto Ristagno on 17/09/15.
//  Copyright © 2015 Fausto Ristagno. All rights reserved.
//

#import "ECCipherData.h"

@implementation ECCipherData

- (instancetype)init
{
    [NSException raise:NSInternalInconsistencyException
                format:@"This class is not intended to be initialized directly."];
    return nil;
}

- (instancetype)initWithData:(NSData *)data
{
    NSAssert(data != nil, @"data must be not nil.");
    
    self = [super init];
    if (self) {
        _rawData = data;
    }
    
    return self;
}

- (NSString *)hexString
{
    NSMutableString *hex = [NSMutableString stringWithCapacity:[self.rawData length]];
    
    [self.rawData enumerateByteRangesUsingBlock:^(const void * _Nonnull bytes, NSRange byteRange, BOOL * _Nonnull stop) {
        for (NSUInteger i = 0; i < byteRange.length; ++i) {
            [hex appendFormat:@"%02x", ((uint8_t*)bytes)[i]];
        }
    }];
    
    return hex;
}

- (NSString *)base64StringWithOptions:(NSDataBase64EncodingOptions)options
{
    return [self.rawData base64EncodedStringWithOptions:options];
}

@end

@implementation ECCipherPlainData

@end

@implementation ECCipherEncryptedData

@end
