//
//  ECBaseHash.h
//  EasyCrypto
//
//  Created by Fausto Ristagno on 19/09/15.
//  Copyright © 2015 Fausto Ristagno. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface ECBaseHash : NSObject

@property (nonatomic, readonly, nonnull) NSData *digest;
@property (nonatomic, readonly, nonnull) NSString *hexDigest;
@property (nonatomic, readonly) NSUInteger digestLength;

- (void)updateWithData:(nonnull NSData *)data;
- (void)updateWithString:(nonnull NSString *)str;
- (void)update:(nonnull NSString *)str; // Shortcut for updateWithString:

@end
