//
//  RSASignature.m
//  CryptoTest
//
//  Created by Fausto Ristagno on 14/09/15.
//  Copyright © 2015 Fausto Ristagno. All rights reserved.
//

#import "RSASignature.h"

@implementation RSASignature

- (instancetype)initWithRawData:(nonnull NSData *)data
{
    self = [super init];
    if (self) {
        _rawData = data;
    }
    
    return self;
}

- (nonnull NSData *)base64data:(NSDataBase64EncodingOptions)options
{
    return [_rawData base64EncodedDataWithOptions:options];
}

- (nonnull NSString *)base64string:(NSDataBase64EncodingOptions)options
{
    return [_rawData base64EncodedStringWithOptions:options];
}

@end
