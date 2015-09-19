//
//  ECDigestObject.h
//  EasyCrypto
//
//  Created by Fausto Ristagno on 16/09/15.
//  Copyright © 2015 Fausto Ristagno. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "ECBaseHash.h"

@interface ECHash : ECBaseHash

- (nonnull instancetype)initWithData:(nonnull NSData *)data;
- (nonnull instancetype)initWithString:(nonnull NSString *)str;

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
