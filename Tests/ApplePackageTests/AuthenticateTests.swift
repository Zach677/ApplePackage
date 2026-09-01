//
//  AuthenticateTests.swift
//  ApplePackage
//
//  Created by qaq on 9/14/25.
//

import AppKit
@testable import ApplePackage
import XCTest

final class ApplePackageAuthenticateTests: XCTestCase {
    override class func setUp() {
        TestConfiguration.bootstrap()
    }

    func testLoginRequestSignsExactPayload() throws {
        let endpoint = try XCTUnwrap(URL(string: "https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate"))
        var signedPayload: Data?

        let request = try Authenticator.makeRequest(
            endpoint: endpoint,
            email: "test@example.com",
            password: "password",
            code: "123456",
            cookies: [],
            deviceIdentifier: "ABCDEF123456",
            signAction: { payload in
                signedPayload = payload
                return "dGVzdC1zaWduYXR1cmU="
            }
        )

        let payload = try XCTUnwrap(signedPayload)
        let propertyList = try XCTUnwrap(
            PropertyListSerialization.propertyList(from: payload, format: nil) as? [String: String]
        )
        XCTAssertEqual(propertyList["appleId"], "test@example.com")
        XCTAssertEqual(propertyList["password"], "password123456")
        XCTAssertEqual(propertyList["guid"], "ABCDEF123456")
        XCTAssertEqual(request.headers.first(name: "X-Apple-ActionSignature"), "dGVzdC1zaWduYXR1cmU=")
    }

    func testCommerceKitSignerProducesSignature() throws {
        try XCTSkipUnless(
            ProcessInfo.processInfo.environment["APPLEPACKAGE_TEST_SAP"] == "1",
            "Set APPLEPACKAGE_TEST_SAP=1 to run the CommerceKit integration test"
        )

        let signature = try AppleActionSigner.sign(Data("ApplePackage SAP integration test".utf8))

        XCTAssertFalse(signature.isEmpty)
        XCTAssertNotNil(Data(base64Encoded: signature))
    }

    @MainActor func testRotatePasswordToken() async throws {
        try XCTSkipUnless(TestConfiguration.hasAuthenticatedAccount, "No authenticated account available")
        try await withAccount(email: testAccountEmail) { account in
            try await Authenticator.rotatePasswordToken(for: &account)
        }
    }

    @MainActor func testAuthenticate() async throws {
        try XCTSkipUnless(TestConfiguration.hasCredentials, "No test credentials available")

        let email = try XCTUnwrap(TestConfiguration.email)
        let password = try XCTUnwrap(TestConfiguration.password)
        let code = TestConfiguration.code ?? ""

        let result = try await Authenticator.authenticate(email: email, password: password, code: code)
        print(result)
        saveLoginAccount(result, for: email)
    }

    @MainActor func testLogin() async throws {
        try XCTSkipIf(TestConfiguration.isCI, "Login requires interactive 2FA, skipping in CI")
        try XCTSkipUnless(TestConfiguration.hasCredentials, "No test credentials available")

        let email = try XCTUnwrap(TestConfiguration.email)
        let password = try XCTUnwrap(TestConfiguration.password)
        var code = TestConfiguration.code ?? ""

        let fileManager = FileManager.default
        let loginAccountPath = "/tmp/applepackage/login_account.txt"
        if fileManager.fileExists(atPath: loginAccountPath) {
            print("login account file exists at \(loginAccountPath), rotating token instead")
            try await withAccount(email: email) { account in
                try await Authenticator.rotatePasswordToken(for: &account)
            }
            return
        }

        do {
            let result = try await Authenticator.authenticate(email: email, password: password, code: code)
            print(result)
            saveLoginAccount(result, for: email)
        } catch {
            print("[?] first attempt failed: \(error)")
            let alert = NSAlert()
            alert.messageText = "Apple Package Auth Failed"
            alert.informativeText = "Please fill out the verification code you received on your device."
            alert.alertStyle = .warning
            alert.addButton(withTitle: "OK")
            alert.runModal()

            // Re-read code from file after user interaction
            if let updatedCode = TestConfiguration.code {
                code = updatedCode
            }
            XCTAssert(!code.isEmpty)
            print("retrying with code: \(code)")
            do {
                let result = try await Authenticator.authenticate(email: email, password: password, code: code)
                print(result)
                saveLoginAccount(result, for: email)
            } catch {
                XCTFail("second attempt failed: \(error)")
            }
        }
    }
}
