//
//  ECCipher.h
//  EasyCrypto
//
//  Created by Fausto Ristagno on 16/09/15.
//  Copyright © 2015 Fausto Ristagno. All rights reserved.
//

#import <Foundation/Foundation.h>


@class ECCipherPlainData, ECCipherEncryptedData;

extern NSString * _Nonnull const ECCipherError;
extern NSInteger ECCipherEncryptionError;
extern NSInteger ECCipherDecryptionError;


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
@property (nonatomic, readonly, nonnull) NSData *key;
@property (nonatomic, readonly, nullable) NSData *iv; // Initilization Vector ([iv length] == [blockSize length])

// Se iv==nil verrà usato un array di bytes nulli
- (nonnull instancetype)initWithDataKey:(nonnull NSData *)key option:(ECCipherOption)opt keySize:(ECCipherKeySize)keySize iv:(nullable NSData *)iv;
- (nonnull instancetype)initWithStringKey:(nonnull NSString *)key option:(ECCipherOption)opt keySize:(ECCipherKeySize)keySize iv:(nullable NSData *)iv;

- (nullable ECCipherEncryptedData *)encryptData:(nonnull NSData *)data error:(NSError * _Nullable * _Nullable)error;
- (nullable ECCipherEncryptedData *)encryptString:(nonnull NSString *)str error:(NSError * _Nullable * _Nullable)error;
- (nullable ECCipherEncryptedData *)encrypt:(nonnull NSString *)str error:(NSError * _Nullable * _Nullable)error;  // Shortcut for encryptString:

- (nullable ECCipherPlainData *)decryptData:(nonnull NSData *)data error:(NSError * _Nullable * _Nullable)error;
- (nullable ECCipherPlainData *)decrypt:(nonnull ECCipherEncryptedData *)data error:(NSError * _Nullable * _Nullable)error;

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
