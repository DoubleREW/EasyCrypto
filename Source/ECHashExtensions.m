//
//  Digest.m
//  EasyCrypto
//
//  Created by Fausto Ristagno on 16/09/15.
//  Copyright © 2015 Fausto Ristagno. All rights reserved.
//

#import "ECDigest.h"
#import "ECDigestObject.h"

@implementation ECDigest
@end

// MARK: Extensions
@implementation NSString (ECDigest)

- (nonnull ECMd2 *)md2
{
    return [[ECMd2 alloc] initWithString:self];
}

- (nonnull ECMd4 *)md4
{
    return [[ECMd4 alloc] initWithString:self];
}

- (nonnull ECMd5 *)md5
{
    return [[ECMd5 alloc] initWithString:self];
}

- (nonnull ECSha1 *)sha1
{
    return [[ECSha1 alloc] initWithString:self];
}

- (nonnull ECSha224 *)sha224
{
    return [[ECSha224 alloc] initWithString:self];
}

- (nonnull ECSha256 *)sha256
{
    return [[ECSha256 alloc] initWithString:self];
}

- (nonnull ECSha384 *)sha384
{
    return [[ECSha384 alloc] initWithString:self];
}

- (nonnull ECSha512 *)sha512
{
    return [[ECSha512 alloc] initWithString:self];
}


@end

@implementation NSData (ECDigest)

- (nonnull ECMd2 *)md2
{
    return [[ECMd2 alloc] initWithData:self];
}

- (nonnull ECMd4 *)md4
{
    return [[ECMd4 alloc] initWithData:self];
}

- (nonnull ECMd5 *)md5
{
    return [[ECMd5 alloc] initWithData:self];
}

- (nonnull ECSha1 *)sha1
{
    return [[ECSha1 alloc] initWithData:self];
}

- (nonnull ECSha224 *)sha224
{
    return [[ECSha224 alloc] initWithData:self];
}

- (nonnull ECSha256 *)sha256
{
    return [[ECSha256 alloc] initWithData:self];
}

- (nonnull ECSha384 *)sha384
{
    return [[ECSha384 alloc] initWithData:self];
}

- (nonnull ECSha512 *)sha512
{
    return [[ECSha512 alloc] initWithData:self];
}


@end
