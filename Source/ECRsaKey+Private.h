//
//  RSAKey+Private.h
//  CryptoTest
//
//  Created by Fausto Ristagno on 14/09/15.
//  Copyright © 2015 Fausto Ristagno. All rights reserved.
//

#import "ECRsaKey.h"

@interface ECRsaKey (Private)

- (nonnull instancetype)initWithSecKey:(nonnull SecKeyRef)key;

@end
