//
//  Digest.h
//  EasyCrypto
//
//  Created by Fausto Ristagno on 16/09/15.
//  Copyright © 2015 Fausto Ristagno. All rights reserved.
//

#import <Foundation/Foundation.h>

@class ECMd2, ECMd4, ECMd5, ECSha1, ECSha224, ECSha256, ECSha384, ECSha512;

@interface ECDigest : NSObject

@end

@interface NSString (ECDigest)

- (nonnull ECMd2 *)md2;
- (nonnull ECMd4 *)md4;
- (nonnull ECMd5 *)md5;
- (nonnull ECSha1 *)sha1;
- (nonnull ECSha224 *)sha224;
- (nonnull ECSha256 *)sha256;
- (nonnull ECSha384 *)sha384;
- (nonnull ECSha512 *)sha512;

@end

@interface NSData (ECDigest)

- (nonnull ECMd2 *)md2;
- (nonnull ECMd4 *)md4;
- (nonnull ECMd5 *)md5;
- (nonnull ECSha1 *)sha1;
- (nonnull ECSha224 *)sha224;
- (nonnull ECSha256 *)sha256;
- (nonnull ECSha384 *)sha384;
- (nonnull ECSha512 *)sha512;

@end
