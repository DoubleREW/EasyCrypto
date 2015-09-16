//
//  RSASignature.h
//  CryptoTest
//
//  Created by Fausto Ristagno on 14/09/15.
//  Copyright © 2015 Fausto Ristagno. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface ECRsaSignature : NSObject

@property (nonatomic, nonnull, readonly) NSData *rawData;


- (nonnull NSData *)base64data:(NSDataBase64EncodingOptions)options;
- (nonnull NSString *)base64string:(NSDataBase64EncodingOptions)options;

@end
