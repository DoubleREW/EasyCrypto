//
//  ECDigestObject+Private.h
//  EasyCrypto
//
//  Created by Fausto Ristagno on 16/09/15.
//  Copyright © 2015 Fausto Ristagno. All rights reserved.
//

#import <CommonCrypto/CommonDigest.h>
#import "ECBaseHash.h"


@interface ECBaseHash ()

@property (nonatomic, strong) NSData *inputData;
@property (nonatomic, strong) NSData *digest;
@property (nonatomic, strong) NSString *hexDigest;
@property (nonatomic, assign) NSInteger digestLength;

- (NSData *)_calculateDigest:(const void *)data len:(CC_LONG)len;
- (NSString *)_calculateHexDigest:(NSData *)data;

@end