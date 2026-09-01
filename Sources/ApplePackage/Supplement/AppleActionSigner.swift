import Foundation

#if os(macOS)
import CommerceKitSigner
import Darwin
#endif

enum AppleActionSigner {
    private static let lock = NSLock()

    static func sign(_ data: Data) throws -> String {
#if os(macOS)
        lock.lock()
        defer { lock.unlock() }

        var output: UnsafeMutablePointer<UInt8>?
        var outputLength = 0
        var errorMessage: UnsafeMutablePointer<CChar>?
        let status = data.withUnsafeBytes { bytes in
            APCommerceKitSign(
                bytes.bindMemory(to: UInt8.self).baseAddress,
                bytes.count,
                &output,
                &outputLength,
                &errorMessage
            )
        }
        defer { free(errorMessage) }

        guard status == 0 else {
            let message = errorMessage.map { String(cString: $0) } ?? "unknown CommerceKit error"
            throw AppleActionSignerError.failed(message)
        }
        guard let output, outputLength > 0 else {
            throw AppleActionSignerError.failed("CommerceKit returned an empty signature")
        }
        defer { free(output) }

        return Data(bytes: output, count: outputLength).base64EncodedString()
#else
        throw AppleActionSignerError.failed("macOS is required")
#endif
    }
}

private enum AppleActionSignerError: LocalizedError {
    case failed(String)

    var errorDescription: String? {
        switch self {
        case let .failed(message):
            return "Apple action signing failed: \(message)"
        }
    }
}
