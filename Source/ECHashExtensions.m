//
//  Digest.m
//  EasyCrypto
//
//  Created by Fausto Ristagno on 16/09/15.
//  Copyright © 2015 Fausto Ristagno. All rights reserved.
//

#import "ECHashExtensions.h"
#import "ECHash.h"


// MARK: Extensions
@implementation NSString (ECHash)

- (nonnull ECHashMD2 *)md2
{
    return [[ECHashMD2 alloc] initWithString:self];
}

- (nonnull ECHashMD4 *)md4
{
    return [[ECHashMD4 alloc] initWithString:self];
}

- (nonnull ECHashMD5 *)md5
{
    return [[ECHashMD5 alloc] initWithString:self];
}

- (nonnull ECHashSHA1 *)sha1
{
    return [[ECHashSHA1 alloc] initWithString:self];
}

- (nonnull ECHashSHA224 *)sha224
{
    return [[ECHashSHA224 alloc] initWithString:self];
}

- (nonnull ECHashSHA256 *)sha256
{
    return [[ECHashSHA256 alloc] initWithString:self];
}

- (nonnull ECHashSHA384 *)sha384
{
    return [[ECHashSHA384 alloc] initWithString:self];
}

- (nonnull ECHashSHA512 *)sha512
{
    return [[ECHashSHA512 alloc] initWithString:self];
}


@end

@implementation NSData (ECHash)

- (nonnull ECHashMD2 *)md2
{
    return [[ECHashMD2 alloc] initWithData:self];
}

- (nonnull ECHashMD4 *)md4
{
    return [[ECHashMD4 alloc] initWithData:self];
}

- (nonnull ECHashMD5 *)md5
{
    return [[ECHashMD5 alloc] initWithData:self];
}

- (nonnull ECHashSHA1 *)sha1
{
    return [[ECHashSHA1 alloc] initWithData:self];
}

- (nonnull ECHashSHA224 *)sha224
{
    return [[ECHashSHA224 alloc] initWithData:self];
}

- (nonnull ECHashSHA256 *)sha256
{
    return [[ECHashSHA256 alloc] initWithData:self];
}

- (nonnull ECHashSHA384 *)sha384
{
    return [[ECHashSHA384 alloc] initWithData:self];
}

- (nonnull ECHashSHA512 *)sha512
{
    return [[ECHashSHA512 alloc] initWithData:self];
}


@end
