//
//  RSAKeyPair+Private.h
//  CryptoTest
//
//  Created by Fausto Ristagno on 14/09/15.
//  Copyright © 2015 Fausto Ristagno. All rights reserved.
//

#import "RSAKeyPair.h"


@class RSAKey;

@interface RSAKeyPair (Private)

- (nonnull instancetype)initWithPublicKey:(nonnull RSAKey *)publicKey privateKey:(nonnull RSAKey *)privateKey;

@end
