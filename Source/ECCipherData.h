//
//  ECCipherPlainData.h
//  EasyCrypto
//
//  Created by Fausto Ristagno on 17/09/15.
//  Copyright © 2015 Fausto Ristagno. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface ECCipherData : NSObject

@property (nonatomic, readonly, nonnull) NSData *rawData;

- (nonnull NSString *)hexString;
- (nonnull NSString *)base64StringWithOptions:(NSDataBase64EncodingOptions)options;

@end

@interface ECCipherEncryptedData : ECCipherData

@end

@interface ECCipherPlainData : ECCipherData

@end
