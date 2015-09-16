//
//  RSAKeyPair.h
//  CryptoTest
//
//  Created by Fausto Ristagno on 14/09/15.
//  Copyright © 2015 Fausto Ristagno. All rights reserved.
//

#import <Foundation/Foundation.h>

@class ECRsaKey;

@interface ECRsaKeyPair : NSObject

@property (nonatomic, readonly, nonnull) ECRsaKey *publicKey;
@property (nonatomic, readonly, nonnull) ECRsaKey *privateKey;

@end
