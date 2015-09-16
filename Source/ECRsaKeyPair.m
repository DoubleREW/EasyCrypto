//
//  RSAKeyPair.m
//  CryptoTest
//
//  Created by Fausto Ristagno on 14/09/15.
//  Copyright © 2015 Fausto Ristagno. All rights reserved.
//

#import "ECRsaKeyPair.h"


@implementation ECRsaKeyPair

- (nonnull instancetype)initWithPublicKey:(nonnull ECRsaKey *)publicKey privateKey:(nonnull ECRsaKey *)privateKey
{
    self = [super init];
    if (self) {
        _publicKey = publicKey;
        _privateKey = privateKey;
    }
    
    return self;
}

@end
