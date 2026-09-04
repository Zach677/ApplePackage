//
//  Authenticate.swift
//  ApplePackage
//
//  Created by QAQ on 2023/10/4.
//

import AsyncHTTPClient
import Foundation
import NIOHTTP1

public struct AuthenticationResult: Sendable {
    public var account: Account
    public var responsePlist: Data

    public init(account: Account, responsePlist: Data) {
        self.account = account
        self.responsePlist = responsePlist
    }
}

public enum Authenticator {
    private enum LoginResponse {
        case success(AuthenticationResult)
        case codeRequired
        case redirect(URL)
        case failure(String)
    }

    private static let maxTransientRequestAttempts = 3
    private static let transientRetryDelayNanoseconds: UInt64 = 250_000_000

    public static func authenticate(
        email: String,
        password: String,
        code: String = "",
        cookies: [Cookie] = [],
        deviceIdentifier: String = Configuration.deviceIdentifier
    ) async throws -> Account {
        try await authenticateWithResponse(
            email: email,
            password: password,
            code: code,
            cookies: cookies,
            deviceIdentifier: deviceIdentifier
        ).account
    }

    public static func authenticateWithResponse(
        email: String,
        password: String,
        code: String = "",
        cookies: [Cookie] = [],
        deviceIdentifier: String = Configuration.deviceIdentifier
    ) async throws -> AuthenticationResult {
        let bagOutput = try await Bag.fetchBag(deviceIdentifier: deviceIdentifier)

        let client = Configuration.makeHTTPClient(redirectConfiguration: .disallow)
        defer { _ = client.shutdown() }

        var requestEndpoint: URL = try createInitialRequestEndpoint(baseURL: bagOutput.authEndpoint, deviceIdentifier: deviceIdentifier)
        var cookies: [Cookie] = cookies
        var storeFront = ""
        var pod: String?
        var redirectAttempt = 0
        let requestData = try makeRequestData(
            email: email,
            password: password,
            code: code,
            deviceIdentifier: deviceIdentifier
        )

        while redirectAttempt <= 3 {
            let response = try await sendAuthenticationRequest {
                let request = try makeRequest(
                    endpoint: requestEndpoint,
                    data: requestData,
                    cookies: cookies
                )
                let response = try await client.execute(request: request).get()
                return (response, response.status.code)
            }
            let result = try parseResponse(
                response,
                email: email,
                password: password,
                code: code,
                cookies: &cookies,
                storeFront: &storeFront,
                pod: &pod
            )
            switch result {
            case let .success(authenticationResult):
                return authenticationResult
            case let .redirect(url):
                requestEndpoint = url
                redirectAttempt += 1
            case .codeRequired:
                try ensureFailed(Strings.authRequiresVerificationCode)
            case let .failure(string):
                try ensureFailed("\(Strings.authFailed): \(string)")
            }
        }

        try ensureFailed(Strings.authFailedUnknown)
    }

    static func sendAuthenticationRequest<Response>(
        execute: () async throws -> (response: Response, statusCode: UInt),
        sleep: (UInt64) async throws -> Void = { try await Task.sleep(nanoseconds: $0) }
    ) async throws -> Response {
        for attempt in 1 ... maxTransientRequestAttempts {
            let result = try await execute()
            guard isTransientAuthenticationStatus(result.statusCode),
                  attempt < maxTransientRequestAttempts
            else {
                return result.response
            }
            try await sleep(UInt64(attempt) * transientRetryDelayNanoseconds)
        }
        preconditionFailure("authentication retry loop must return")
    }

    private static func isTransientAuthenticationStatus(_ statusCode: UInt) -> Bool {
        statusCode == 204 || statusCode == 404 || statusCode / 100 == 5
    }

    public static func rotatePasswordToken(for account: inout Account) async throws {
        let newAccount = try await authenticate(
            email: account.email,
            password: account.password,
            code: "",
            cookies: account.cookie
        )
        account = newAccount
    }

    private static func createInitialRequestEndpoint(
        baseURL: URL,
        deviceIdentifier: String
    ) throws -> URL {
        guard var comps = URLComponents(url: baseURL, resolvingAgainstBaseURL: true) else {
            try ensureFailed("\(Strings.invalidAuthEndpoint): \(baseURL)")
        }
        comps.queryItems = [
            URLQueryItem(name: "guid", value: deviceIdentifier),
        ]
        return try comps.url.get()
    }

    static func makeRequest(
        endpoint: URL,
        email: String,
        password: String,
        code: String,
        cookies: [Cookie],
        deviceIdentifier: String,
        signAction: (Data) throws -> String = AppleActionSigner.sign
    ) throws -> HTTPClient.Request {
        let data = try makeRequestData(
            email: email,
            password: password,
            code: code,
            deviceIdentifier: deviceIdentifier
        )
        return try makeRequest(
            endpoint: endpoint,
            data: data,
            cookies: cookies,
            signAction: signAction
        )
    }

    private static func makeRequestData(
        email: String,
        password: String,
        code: String,
        deviceIdentifier: String
    ) throws -> Data {
        let parameters: [String: String] = [
            "appleId": email,
            "attempt": "\(code.isEmpty ? "4" : "2")",
            "guid": deviceIdentifier,
            "password": "\(password)\(code)",
            "rmp": "0",
            "why": "signIn",
        ]
        return try PropertyListSerialization.data(
            fromPropertyList: parameters,
            format: .xml,
            options: 0
        )
    }

    private static func makeRequest(
        endpoint: URL,
        data: Data,
        cookies: [Cookie],
        signAction: (Data) throws -> String = AppleActionSigner.sign
    ) throws -> HTTPClient.Request {
        var headers: [(String, String)] = [
            ("User-Agent", Configuration.userAgent),
            ("Content-Type", "application/x-apple-plist"),
        ]
        for item in cookies.buildCookieHeader(endpoint) {
            headers.append(item)
        }
        let actionSignature = try signAction(data)
        APLogger.logRequest(method: "POST", url: endpoint.absoluteString, headers: headers)
        headers.append(("X-Apple-ActionSignature", actionSignature))
        return try .init(
            url: endpoint.absoluteString,
            method: .POST,
            headers: .init(headers),
            body: .data(data)
        )
    }

    private static func parseResponse(
        _ response: HTTPClient.Response,
        email: String,
        password: String,
        code: String,
        cookies: inout [Cookie],
        storeFront: inout String,
        pod: inout String?
    ) throws -> LoginResponse {
        APLogger.logResponse(
            status: response.status.code,
            headers: response.headers.map { ($0.name, $0.value) },
            bodySize: response.body?.readableBytes
        )

        cookies.mergeCookies(response.cookies)

        let readStoreFrontValue = response
            .headers["x-set-apple-store-front"]
            .filter { !$0.isEmpty }
            .compactMap { $0.components(separatedBy: "-").first }
            .filter { !$0.isEmpty }
        assert(readStoreFrontValue.count <= 1)
        if let first = readStoreFrontValue.first {
            storeFront = first
        }

        if let podValue = response.headers.first(name: "pod"), !podValue.isEmpty {
            pod = podValue
            APLogger.info("auth: received pod value: \(podValue)")
        }

        let redirectStatuses: [HTTPResponseStatus] = [.movedPermanently, .found, .seeOther, .temporaryRedirect, .permanentRedirect]
        if redirectStatuses.contains(response.status) {
            guard let location = response.headers.first(name: "location"),
                  let url = URL(string: location)
            else {
                return .failure(Strings.failedToRetrieveRedirect)
            }
            return .redirect(url)
        }

        guard var body = response.body,
              let data = body.readData(length: body.readableBytes)
        else {
            return .failure("response body is empty (code: \(response.status.code))")
        }

        let listItem = try PropertyListSerialization.propertyList(
            from: data,
            options: [],
            format: nil
        )
        let dic = try (listItem as? [String: Any]).get(Strings.responseNotDictionary)

        if let failureType = dic["failureType"] as? String,
           failureType.isEmpty,
           code.isEmpty,
           let customerMessage = dic["customerMessage"] as? String,
           customerMessage == "MZFinance.BadLogin.Configurator_message"
        {
            return .codeRequired
        }

        if let failureType = dic["failureType"] as? String, failureType == "5005" {
            return .failure(Strings.invalid2FACode)
        }

        let failureMessage = (dic["dialog"] as? [String: Any])?["explanation"] as? String ?? (dic["customerMessage"] as? String)
        let accountInfoDic = try (dic["accountInfo"] as? [String: Any]).get(failureMessage ?? Strings.missingAccountInfo)
        let addressInfoDic = try (accountInfoDic["address"] as? [String: Any]).get(failureMessage ?? Strings.missingAddress)

        let account = try Account(
            email: email,
            password: password,
            appleId: accountInfoDic["appleId"] as? String,
            store: storeFront,
            firstName: addressInfoDic["firstName"] as? String,
            lastName: addressInfoDic["lastName"] as? String,
            passwordToken: dic["passwordToken"] as? String,
            directoryServicesIdentifier: dic["dsPersonId"] as? String,
            cookie: cookies,
            pod: pod
        )
        return .success(AuthenticationResult(account: account, responsePlist: data))
    }
}
