//
//  RSASignature+Private.h
//  CryptoTest
//
//  Created by Fausto Ristagno on 14/09/15.
//  Copyright © 2015 Fausto Ristagno. All rights reserved.
//

#import "RSASignature.h"

@class NSData;

@interface RSASignature (Private)

- (nonnull instancetype)initWithRawData:(nonnull NSData *)data;

@end
