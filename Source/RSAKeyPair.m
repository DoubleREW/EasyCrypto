//
//  RSAKeyPair.m
//  CryptoTest
//
//  Created by Fausto Ristagno on 14/09/15.
//  Copyright © 2015 Fausto Ristagno. All rights reserved.
//

#import "RSAKeyPair.h"


@implementation RSAKeyPair

- (nonnull instancetype)initWithPublicKey:(nonnull RSAKey *)publicKey privateKey:(nonnull RSAKey *)privateKey
{
    self = [super init];
    if (self) {
        _publicKey = publicKey;
        _privateKey = privateKey;
    }
    
    return self;
}

@end
