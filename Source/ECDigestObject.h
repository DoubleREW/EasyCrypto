//
//  ECDigestObject.h
//  EasyCrypto
//
//  Created by Fausto Ristagno on 16/09/15.
//  Copyright © 2015 Fausto Ristagno. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface ECDigestObject : NSObject

@property (nonatomic, readonly, nonnull) NSData *digest;
@property (nonatomic, readonly, nonnull) NSString *hexDigest;
@property (nonatomic, readonly) NSUInteger digestLength; // In bit


- (nonnull instancetype)initWithData:(nonnull NSData *)data;
- (nonnull instancetype)initWithString:(nonnull NSString *)str;

- (void)updateWithData:(nonnull NSData *)data;
- (void)updateWithString:(nonnull NSData *)data;

@end

@interface ECMd2 : ECDigestObject
@end

@interface ECMd4 : ECDigestObject
@end

@interface ECMd5 : ECDigestObject
@end

@interface ECSha1 : ECDigestObject
@end

@interface ECSha224 : ECDigestObject
@end

@interface ECSha256 : ECDigestObject
@end

@interface ECSha384 : ECDigestObject
@end

@interface ECSha512 : ECDigestObject
@end
