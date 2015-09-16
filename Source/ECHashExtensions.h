//
//  Digest.h
//  EasyCrypto
//
//  Created by Fausto Ristagno on 16/09/15.
//  Copyright © 2015 Fausto Ristagno. All rights reserved.
//

#import <Foundation/Foundation.h>

@class ECHashMD2, ECHashMD4, ECHashMD5, ECHashSHA1, ECHashSHA224, ECHashSHA256, ECHashSHA384, ECHashSHA512;


@interface NSString (ECHash)

- (nonnull ECHashMD2 *)md2;
- (nonnull ECHashMD4 *)md4;
- (nonnull ECHashMD5 *)md5;
- (nonnull ECHashSHA1 *)sha1;
- (nonnull ECHashSHA224 *)sha224;
- (nonnull ECHashSHA256 *)sha256;
- (nonnull ECHashSHA384 *)sha384;
- (nonnull ECHashSHA512 *)sha512;

@end

@interface NSData (ECHash)

- (nonnull ECHashMD2 *)md2;
- (nonnull ECHashMD4 *)md4;
- (nonnull ECHashMD5 *)md5;
- (nonnull ECHashSHA1 *)sha1;
- (nonnull ECHashSHA224 *)sha224;
- (nonnull ECHashSHA256 *)sha256;
- (nonnull ECHashSHA384 *)sha384;
- (nonnull ECHashSHA512 *)sha512;

@end
