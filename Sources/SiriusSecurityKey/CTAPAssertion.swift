import Foundation

public enum CTAPPlanOperation: String, Sendable {
  case getAssertion
}

/// Opaque, immutable CTAP execution plan compiled from an authorized ceremony
/// and validated authenticator capabilities.
///
/// Encoded command bytes and replay operations are intentionally not public.
public struct ImmutableCTAPPlan: Sendable {
  public let operation: CTAPPlanOperation
  public let isDiscoverable: Bool
  public let requiresUserVerification: Bool
  public let maximumAssertionCount: Int

  let initialRequest: CTAPRequest
  let ceremony: ValidatedWebAuthnAssertionCeremony
  let expectedRelyingPartyIDHash: Data
  let maximumMessageSize: Int

  var nextAssertionRequest: CTAPRequest {
    CTAPRequest(command: 0x08)
  }
}

/// Compiles exactly one CTAP2 assertion route or fails before dispatch.
public enum WebAuthnAssertionPlanCompiler {
  public static func compile(
    ceremony: ValidatedWebAuthnAssertionCeremony,
    authenticatorInfo: AuthenticatorInfo
  ) throws -> ImmutableCTAPPlan {
    let supportedCTAP2Versions: Set<String> = ["FIDO_2_0", "FIDO_2_1", "FIDO_2_2"]
    guard !supportedCTAP2Versions.isDisjoint(with: authenticatorInfo.versions) else {
      throw WebAuthnError.authenticatorCapabilityMismatch
    }

    let allowCredentials = ceremony.allowCredentials
    if let maximum = authenticatorInfo.maximumCredentialCountInList,
      allowCredentials.count > Int(maximum)
    {
      throw WebAuthnError.credentialListTooLarge
    }
    if let maximumIDLength = authenticatorInfo.maximumCredentialIDLength,
      allowCredentials.contains(where: { $0.id.count > Int(maximumIDLength) })
    {
      throw WebAuthnError.credentialIDOutOfBounds
    }

    let builtInUserVerification = authenticatorInfo.options["uv"] == true
    let alwaysRequiresUserVerification = authenticatorInfo.options["alwaysUv"] == true
    let requiresUserVerification: Bool
    if ceremony.isDiscoverable {
      guard authenticatorInfo.options["rk"] == true else {
        throw WebAuthnError.discoverableCredentialsUnsupported
      }
      guard builtInUserVerification else {
        throw WebAuthnError.userVerificationUnavailable
      }
      requiresUserVerification = true
    } else {
      switch ceremony.requestedUserVerification {
      case .required:
        guard builtInUserVerification else {
          throw WebAuthnError.userVerificationUnavailable
        }
        requiresUserVerification = true
      case .preferred:
        requiresUserVerification = builtInUserVerification
      case .discouraged:
        requiresUserVerification = alwaysRequiresUserVerification
      }
    }

    var entries = [
      CBORMapEntry(
        key: .unsigned(1),
        value: .textString(ceremony.relyingPartyID.value)
      ),
      CBORMapEntry(
        key: .unsigned(2),
        value: .byteString(ceremony.clientData.hash)
      ),
    ]
    if !allowCredentials.isEmpty {
      entries.append(
        CBORMapEntry(
          key: .unsigned(3),
          value: .array(allowCredentials.map(credentialDescriptorValue))
        )
      )
    }
    if requiresUserVerification {
      entries.append(
        CBORMapEntry(
          key: .unsigned(5),
          value: .map([
            CBORMapEntry(key: .textString("uv"), value: .boolean(true))
          ])
        )
      )
    }

    let declaredMaximum = authenticatorInfo.maximumMessageSize.map(Int.init) ?? 1_024
    let maximumMessageSize = min(declaredMaximum, 128 << 10)
    let payload: Data
    do {
      payload = try CanonicalCBOR.encode(
        .map(entries),
        limits: CBORLimits(
          maximumMessageSize: maximumMessageSize,
          maximumNestingDepth: 6,
          maximumCollectionCount: 128,
          maximumStringSize: maximumMessageSize,
          maximumTotalItems: 512
        )
      )
    } catch CBORError.messageTooLarge {
      throw WebAuthnError.ctapMessageTooLarge
    } catch {
      throw WebAuthnError.authenticatorCapabilityMismatch
    }

    return ImmutableCTAPPlan(
      operation: .getAssertion,
      isDiscoverable: ceremony.isDiscoverable,
      requiresUserVerification: requiresUserVerification,
      maximumAssertionCount: 64,
      initialRequest: CTAPRequest(command: 0x02, payload: payload),
      ceremony: ceremony,
      expectedRelyingPartyIDHash: ProtocolCryptography.sha256(
        Data(ceremony.relyingPartyID.value.utf8)
      ),
      maximumMessageSize: maximumMessageSize
    )
  }

  private static func credentialDescriptorValue(
    _ descriptor: WebAuthnCredentialDescriptor
  ) -> CBORValue {
    .map([
      CBORMapEntry(key: .textString("id"), value: .byteString(descriptor.id)),
      CBORMapEntry(key: .textString("type"), value: .textString("public-key")),
    ])
  }
}

struct CTAPAssertionUser: Sendable {
  let id: Data
  let name: String?
  let displayName: String?
}

struct CTAPAssertionResponse: Sendable {
  let credentialID: Data
  let authenticatorData: AuthenticatorData
  let signature: Data
  let user: CTAPAssertionUser?
  let numberOfCredentials: Int?
  let userSelected: Bool?
  let rawResponse: CBORValue
}

enum CTAPAssertionResponseParser {
  static func parse(
    _ response: CTAPResponse,
    plan: ImmutableCTAPPlan,
    isFirstResponse: Bool
  ) throws -> CTAPAssertionResponse {
    guard response.status == 0 else {
      throw WebAuthnError.ctapStatus(response.status)
    }

    let raw: CBORValue
    do {
      raw = try CanonicalCBOR.decode(
        response.payload,
        limits: CBORLimits(
          maximumMessageSize: max(plan.maximumMessageSize, 1_024),
          maximumNestingDepth: 8,
          maximumCollectionCount: 128,
          maximumStringSize: 128 << 10,
          maximumTotalItems: 512
        )
      )
    } catch {
      throw WebAuthnError.invalidAssertionResponse
    }
    guard case .map = raw,
      case .byteString(let authenticatorDataBytes)? = raw.value(forUnsignedKey: 2),
      case .byteString(let signature)? = raw.value(forUnsignedKey: 3),
      !signature.isEmpty,
      signature.count <= 8_192
    else {
      throw WebAuthnError.invalidAssertionResponse
    }

    let authenticatorData = try AuthenticatorDataParser.parseAssertion(
      authenticatorDataBytes
    )
    guard authenticatorData.relyingPartyIDHash == plan.expectedRelyingPartyIDHash else {
      throw WebAuthnError.relyingPartyHashMismatch
    }
    guard authenticatorData.flags.contains(.userPresent) else {
      throw WebAuthnError.userPresenceMissing
    }
    if plan.requiresUserVerification {
      guard authenticatorData.flags.contains(.userVerified) else {
        throw WebAuthnError.userVerificationMissing
      }
    }

    let credentialID = try resolvedCredentialID(raw: raw, plan: plan)
    let user = try parseUser(raw.value(forUnsignedKey: 4))
    if plan.isDiscoverable {
      guard user != nil else {
        throw WebAuthnError.invalidAssertionResponse
      }
    }
    if !authenticatorData.flags.contains(.userVerified),
      user?.name != nil || user?.displayName != nil
    {
      throw WebAuthnError.invalidAssertionResponse
    }

    let numberOfCredentials: Int?
    if let value = raw.value(forUnsignedKey: 5) {
      guard isFirstResponse,
        case .unsigned(let rawCount) = value,
        rawCount > 0,
        rawCount <= UInt32(plan.maximumAssertionCount),
        plan.isDiscoverable
      else {
        throw rawCountIsExcessive(value, maximum: plan.maximumAssertionCount)
          ? WebAuthnError.tooManyAssertions
          : WebAuthnError.invalidAssertionResponse
      }
      numberOfCredentials = Int(rawCount)
    } else {
      numberOfCredentials = nil
    }

    let userSelected: Bool?
    if let value = raw.value(forUnsignedKey: 6) {
      guard isFirstResponse, numberOfCredentials == nil,
        case .boolean(let selected) = value,
        plan.isDiscoverable
      else {
        throw WebAuthnError.invalidAssertionResponse
      }
      userSelected = selected
    } else {
      userSelected = nil
    }

    return CTAPAssertionResponse(
      credentialID: credentialID,
      authenticatorData: authenticatorData,
      signature: Data(signature),
      user: user,
      numberOfCredentials: numberOfCredentials,
      userSelected: userSelected,
      rawResponse: raw
    )
  }

  static func accountCandidates(
    for responses: [CTAPAssertionResponse],
    maximumAssertionCount: Int
  ) throws -> [WebAuthnAccountCandidate] {
    guard responses.count > 1, responses.count <= maximumAssertionCount else {
      throw WebAuthnError.invalidAssertionResponse
    }
    return try responses.enumerated().map { index, response in
      guard let user = response.user else {
        throw WebAuthnError.invalidAssertionResponse
      }
      return WebAuthnAccountCandidate(
        userHandle: user.id,
        name: user.name,
        displayName: user.displayName,
        responseIndex: index
      )
    }
  }

  static func finish(
    responses: [CTAPAssertionResponse],
    plan: ImmutableCTAPPlan,
    selectedResponseIndex: Int?
  ) throws -> WebAuthnAssertion {
    guard !responses.isEmpty, responses.count <= plan.maximumAssertionCount else {
      throw WebAuthnError.tooManyAssertions
    }

    let selected: CTAPAssertionResponse
    if responses.count == 1 {
      guard selectedResponseIndex == nil || selectedResponseIndex == 0 else {
        throw WebAuthnError.invalidAccountSelection
      }
      selected = responses[0]
    } else {
      guard let selectedResponseIndex else {
        throw WebAuthnError.accountSelectionRequired
      }
      let candidates = try accountCandidates(
        for: responses,
        maximumAssertionCount: plan.maximumAssertionCount
      )
      guard candidates.indices.contains(selectedResponseIndex) else {
        throw WebAuthnError.invalidAccountSelection
      }
      selected = responses[candidates[selectedResponseIndex].responseIndex]
    }

    return WebAuthnAssertion(
      credentialID: selected.credentialID,
      clientDataJSON: plan.ceremony.clientData.json,
      authenticatorData: selected.authenticatorData.rawBytes,
      signature: selected.signature,
      userHandle: selected.user?.id,
      signCount: selected.authenticatorData.signCount,
      userWasPresent: selected.authenticatorData.flags.contains(.userPresent),
      userWasVerified: selected.authenticatorData.flags.contains(.userVerified),
      backupEligible: selected.authenticatorData.flags.contains(.backupEligible),
      backupState: selected.authenticatorData.flags.contains(.backupState),
      authenticatorExtensionOutputs: selected.authenticatorData.extensionOutputs,
      authenticatorAttachment: .hybrid
    )
  }

  private static func resolvedCredentialID(
    raw: CBORValue,
    plan: ImmutableCTAPPlan
  ) throws -> Data {
    if let value = raw.value(forUnsignedKey: 1) {
      guard case .map(let entries) = value,
        case .textString("public-key")? = value.value(forTextKey: "type"),
        case .byteString(let id)? = value.value(forTextKey: "id"),
        !id.isEmpty,
        id.count <= 1_024,
        entries.allSatisfy({ entry in
          if case .textString = entry.key { return true }
          return false
        })
      else {
        throw WebAuthnError.invalidAssertionResponse
      }
      if !plan.ceremony.allowCredentials.isEmpty,
        !plan.ceremony.allowCredentials.contains(where: { $0.id == id })
      {
        throw WebAuthnError.credentialMismatch
      }
      return Data(id)
    }

    guard plan.ceremony.allowCredentials.count == 1 else {
      throw WebAuthnError.invalidAssertionResponse
    }
    return plan.ceremony.allowCredentials[0].id
  }

  private static func parseUser(_ value: CBORValue?) throws -> CTAPAssertionUser? {
    guard let value else {
      return nil
    }
    guard case .map(let entries) = value,
      case .byteString(let id)? = value.value(forTextKey: "id"),
      !id.isEmpty,
      id.count <= 64,
      entries.allSatisfy({ entry in
        if case .textString = entry.key { return true }
        return false
      })
    else {
      throw WebAuthnError.invalidAssertionResponse
    }

    let name = try optionalBoundedText(value.value(forTextKey: "name"))
    let displayName = try optionalBoundedText(value.value(forTextKey: "displayName"))
    return CTAPAssertionUser(
      id: Data(id),
      name: name,
      displayName: displayName
    )
  }

  private static func optionalBoundedText(_ value: CBORValue?) throws -> String? {
    guard let value else {
      return nil
    }
    guard case .textString(let string) = value, string.utf8.count <= 256 else {
      throw WebAuthnError.invalidAssertionResponse
    }
    return string
  }

  private static func rawCountIsExcessive(
    _ value: CBORValue,
    maximum: Int
  ) -> Bool {
    guard case .unsigned(let count) = value else {
      return false
    }
    return count > UInt32(maximum)
  }
}

extension CBORValue {
  func value(forTextKey key: String) -> CBORValue? {
    guard case .map(let entries) = self else {
      return nil
    }
    return entries.first { $0.key == .textString(key) }?.value
  }
}
