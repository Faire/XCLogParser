// Copyright (c) 2019 Spotify AB.
//
// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

import Foundation
#if canImport(CryptoKit)
import CryptoKit
#endif
import CommonCrypto

// Thanks to https://pewpewthespells.com/blog/xcode_deriveddata_hashes.html for
// the initial Objective-C implementation.
public class XcodeHasher {

    enum HashingError: Error {
        case invalidPartitioning
    }

    public static func hashString(for path: String) throws -> String {
        // Initialize a 28 `String` array since we can't initialize empty `Character`s.
        var result = Array(repeating: "", count: 28)

        // Compute md5 hash of the path
        let digest = md5Hash(for: path)

        // Split 16 bytes into two chunks of 8 bytes each.
        let partitions = stride(from: 0, to: digest.count, by: 8).map {
            Array(digest[$0..<Swift.min($0 + 8, digest.count)])
        }
        guard let firstHalf = partitions.first else { throw HashingError.invalidPartitioning }
        guard let secondHalf = partitions.last else { throw HashingError.invalidPartitioning }

        // We would need to reverse the bytes, so we just read them in big endian.
        #if swift(>=5.0)
        var startValue = UInt64(bigEndian: Data(firstHalf).withUnsafeBytes { $0.load(as: UInt64.self) })
        #else
        var startValue = UInt64(bigEndian: Data(firstHalf).withUnsafeBytes { $0.pointee })
        #endif
        for index in stride(from: 13, through: 0, by: -1) {
            // Take the startValue % 26 to restrict to alphabetic characters and add 'a' scalar value (97).
            let char = String(UnicodeScalar(Int(startValue % 26) + 97)!)
            result[index] = char
            startValue /= 26
        }
        // We would need to reverse the bytes, so we just read them in big endian.
        #if swift(>=5.0)
        startValue = UInt64(bigEndian: Data(secondHalf).withUnsafeBytes { $0.load(as: UInt64.self) })
        #else
        startValue = UInt64(bigEndian: Data(secondHalf).withUnsafeBytes { $0.pointee })
        #endif
        for index in stride(from: 27, through: 14, by: -1) {
            // Take the startValue % 26 to restrict to alphabetic characters and add 'a' scalar value (97).
            let char = String(UnicodeScalar(Int(startValue % 26) + 97)!)
            result[index] = char
            startValue /= 26
        }

        return result.joined()
    }
    
    private static func md5Hash(for string: String) -> [UInt8] {
        let data = Data(string.utf8)
        
        #if canImport(CryptoKit) && swift(>=5.0)
        if #available(macOS 10.15, iOS 13.0, watchOS 6.0, tvOS 13.0, *) {
            let digest = Insecure.MD5.hash(data: data)
            return Array(digest)
        }
        #endif
        
        // Fallback to CommonCrypto
        var digest = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
        data.withUnsafeBytes { bufferPointer in
            _ = CC_MD5(bufferPointer.baseAddress, CC_LONG(data.count), &digest)
        }
        return digest
    }
}
