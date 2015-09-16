//
//  ECDigestObject+Private.h
//  EasyCrypto
//
//  Created by Fausto Ristagno on 16/09/15.
//  Copyright © 2015 Fausto Ristagno. All rights reserved.
//

#import <CommonCrypto/CommonDigest.h>
#import "ECHash.h"


@interface ECHash (Private)

- (NSData *)_calculateDigest:(const void *)data len:(CC_LONG)len;
- (NSString *)_calculateHexDigest:(NSData *)data;

@end