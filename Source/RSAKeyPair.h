//
//  RSAKeyPair.h
//  CryptoTest
//
//  Created by Fausto Ristagno on 14/09/15.
//  Copyright © 2015 Fausto Ristagno. All rights reserved.
//

#import <Foundation/Foundation.h>

@class RSAKey;

@interface RSAKeyPair : NSObject

@property (nonatomic, readonly, nonnull) RSAKey *publicKey;
@property (nonatomic, readonly, nonnull) RSAKey *privateKey;

@end
