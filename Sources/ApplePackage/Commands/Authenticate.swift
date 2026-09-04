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
        case retryWithoutCookies
        case failure(String)
    }

    enum RedirectHandling: Equatable {
        case follow(URL)
        case parseBody
        case retryWithoutCookies
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
        var didClearCookies = false
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
                currentURL: requestEndpoint,
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
            case .retryWithoutCookies:
                guard !didClearCookies else {
                    try ensureFailed("\(Strings.authFailed): \(Strings.failedToRetrieveRedirect)")
                }
                cookies = []
                didClearCookies = true
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
        let url = try comps.url.get()
        return Bag.normalizedAuthEndpoint(from: url.absoluteString) ?? url
    }

    /// Apple's native auth host 301s `/fast` (no trailing slash) to an HTML page
    /// with no Location header. Recover by adding the slash, and trim/resolve
    /// any Location we do receive against the current request URL.
    static func resolvedRedirectURL(locationHeader: String?, currentURL: URL) -> URL? {
        if let raw = locationHeader?.trimmingCharacters(in: .whitespacesAndNewlines), !raw.isEmpty {
            let parsed = URL(string: raw, relativeTo: currentURL)?.absoluteURL ?? URL(string: raw)
            if let parsed {
                return Bag.normalizedAuthEndpoint(from: parsed.absoluteString) ?? parsed
            }
        }

        guard let normalized = Bag.normalizedAuthEndpoint(from: currentURL.absoluteString),
              normalized.absoluteString != currentURL.absoluteString
        else {
            return nil
        }
        return normalized
    }

    /// Cookie-backed reauth often 302s with no Location. Follow Location when we
    /// have one; otherwise parse a plist body or retry once without cookies.
    static func redirectHandling(
        status: HTTPResponseStatus,
        locationHeader: String?,
        currentURL: URL,
        bodyLength: Int
    ) -> RedirectHandling? {
        let redirectStatuses: [HTTPResponseStatus] = [
            .movedPermanently, .found, .seeOther, .temporaryRedirect, .permanentRedirect,
        ]
        guard redirectStatuses.contains(status) else { return nil }
        if let url = resolvedRedirectURL(locationHeader: locationHeader, currentURL: currentURL) {
            return .follow(url)
        }
        if bodyLength > 0 {
            return .parseBody
        }
        return .retryWithoutCookies
    }

    static func locationCandidate(from headers: HTTPHeaders) -> String? {
        for name in ["location", "x-apple-orig-url"] {
            if let value = headers.first(name: name)?.trimmingCharacters(in: .whitespacesAndNewlines),
               !value.isEmpty
            {
                return value
            }
        }
        return nil
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
        currentURL: URL,
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

        if let handling = redirectHandling(
            status: response.status,
            locationHeader: locationCandidate(from: response.headers),
            currentURL: currentURL,
            bodyLength: response.body?.readableBytes ?? 0
        ) {
            switch handling {
            case let .follow(url):
                return .redirect(url)
            case .retryWithoutCookies:
                return .retryWithoutCookies
            case .parseBody:
                break
            }
        }

        guard var body = response.body,
              let data = body.readData(length: body.readableBytes)
        else {
            return .failure("response body is empty (code: \(response.status.code))")
        }

        let listItem: Any
        do {
            listItem = try PropertyListSerialization.propertyList(
                from: data,
                options: [],
                format: nil
            )
        } catch {
            if redirectHandling(
                status: response.status,
                locationHeader: nil,
                currentURL: currentURL,
                bodyLength: 0
            ) != nil
            {
                return .retryWithoutCookies
            }
            throw error
        }
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
