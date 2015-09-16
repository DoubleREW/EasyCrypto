//
//  ECDigestObject.h
//  EasyCrypto
//
//  Created by Fausto Ristagno on 16/09/15.
//  Copyright © 2015 Fausto Ristagno. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface ECHash : NSObject

@property (nonatomic, readonly, nonnull) NSData *digest;
@property (nonatomic, readonly, nonnull) NSString *hexDigest;
@property (nonatomic, readonly) NSUInteger digestLength; // In bit


- (nonnull instancetype)initWithData:(nonnull NSData *)data;
- (nonnull instancetype)initWithString:(nonnull NSString *)str;

- (void)updateWithData:(nonnull NSData *)data;
- (void)updateWithString:(nonnull NSString *)str;
- (void)update:(nonnull NSString *)str; // Shortcut for updateWithString:

@end

@interface ECHashMD2 : ECHash
@end

@interface ECHashMD4 : ECHash
@end

@interface ECHashMD5 : ECHash
@end

@interface ECHashSHA1 : ECHash
@end

@interface ECHashSHA224 : ECHash
@end

@interface ECHashSHA256 : ECHash
@end

@interface ECHashSHA384 : ECHash
@end

@interface ECHashSHA512 : ECHash
@end
