//
//  ECCipher.h
//  EasyCrypto
//
//  Created by Fausto Ristagno on 16/09/15.
//  Copyright © 2015 Fausto Ristagno. All rights reserved.
//

#import <Foundation/Foundation.h>


typedef NS_ENUM(NSUInteger, ECCipherAlgorithm) {
    ECCipherAlgorithmAES128 = 0,
    ECCipherAlgorithmAES = 0,
    ECCipherAlgorithmDES,
    ECCipherAlgorithm3DES,
    ECCipherAlgorithmCAST,
    ECCipherAlgorithmRC4,
    ECCipherAlgorithmRC2,
    ECCipherAlgorithmBlowfish
};

typedef NS_ENUM(NSUInteger, ECCipherOption) {
    ECCipherOptionPKCS7Padding   = 0x0001,
    ECCipherOptionECBMode        = 0x0002
};

typedef NS_ENUM(NSUInteger, ECCipherKeySize) {
    ECCipherKeySizeAES128          = 16,
    ECCipherKeySizeAES192          = 24,
    ECCipherKeySizeAES256          = 32,
    ECCipherKeySizeDES             = 8,
    ECCipherKeySize3DES            = 24,
    ECCipherKeySizeMinCAST         = 5,
    ECCipherKeySizeMaxCAST         = 16,
    ECCipherKeySizeMinRC4          = 1,
    ECCipherKeySizeMaxRC4          = 512,
    ECCipherKeySizeMinRC2          = 1,
    ECCipherKeySizeMaxRC2          = 128,
    ECCipherKeySizeMinBlowfish     = 8,
    ECCipherKeySizeMaxBlowfish     = 56,
};

typedef NS_ENUM(NSUInteger, ECCipherBlockSize) {
    /* AES */
    ECCipherBlockSizeAES128        = 16,
    /* DES */
    ECCipherBlockSizeDES           = 8,
    /* 3DES */
    ECCipherBlockSize3DES          = 8,
    /* CAST */
    ECCipherBlockSizeCAST          = 8,
    ECCipherBlockSizeRC2           = 8,
    ECCipherBlockSizeBlowfish      = 8,
};

@interface ECCipher : NSObject

@property (nonatomic, readonly) ECCipherAlgorithm algorithm;
@property (nonatomic, readonly) ECCipherBlockSize blockSize; // Byte
@property (nonatomic, readonly) ECCipherOption option;
@property (nonatomic, readonly) ECCipherKeySize keySize; // Byte
@property (nonatomic, readonly) NSData *key;
@property (nonatomic, readonly) NSData *iv; // Initilization Vector ([iv length] == [blockSize length])

// Se iv==nil verrà usato un array di bytes nulli
- (instancetype)initWithDataKey:(NSData *)key option:(ECCipherOption)opt keySize:(ECCipherKeySize)keySize iv:(NSData *)iv;
- (instancetype)initWithStringKey:(NSString *)key option:(ECCipherOption)opt keySize:(ECCipherKeySize)keySize iv:(NSData *)iv;

- (NSData *)encryptData:(NSData *)data;
- (NSData *)encryptString:(NSString *)str;
- (NSData *)encrypt:(NSString *)str;  // Shortcut for encryptString: 

- (NSData *)decrypt:(NSData *)data;

@end

@interface ECCipherAES : ECCipher
@end

@interface ECCipherDES : ECCipher
@end

@interface ECCipher3DES : ECCipher
@end

@interface ECCipherCAST : ECCipher
@end

/*
@interface ECCipherRC4 : ECCipher
@end
*/

@interface ECCipherRC2 : ECCipher
@end

@interface ECCipherBlowfish : ECCipher
@end
