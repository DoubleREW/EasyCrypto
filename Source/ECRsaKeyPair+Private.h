//
//  RSAKeyPair+Private.h
//  CryptoTest
//
//  Created by Fausto Ristagno on 14/09/15.
//  Copyright © 2015 Fausto Ristagno. All rights reserved.
//

#import "ECRsaKeyPair.h"


@class ECRsaKey;

@interface ECRsaKeyPair (Private)

- (nonnull instancetype)initWithPublicKey:(nonnull ECRsaKey *)publicKey privateKey:(nonnull ECRsaKey *)privateKey;

@end
