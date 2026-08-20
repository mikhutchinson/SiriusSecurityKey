import Foundation
import WebURL

enum PublicSuffixDatabaseError: Error, Sendable, Equatable {
  case resourceUnavailable
  case invalidEncoding
  case invalidRule
  case resourceLimitExceeded
}

/// Immutable Public Suffix List matcher used for RP ID authorization.
///
/// The bundled rule bytes are pinned in `References/upstream-lock.json` and
/// include both ICANN and private domains. Hosts and rules are compared only
/// after WebURL's pinned UTS #46 normalization has produced canonical ASCII.
struct PublicSuffixDatabase: Sendable {
  private static let maximumSourceBytes = 1 << 20
  private static let maximumRuleCount = 20_000
  private static let maximumRuleBytes = 255

  private let exactRules: Set<String>
  private let wildcardRules: Set<String>
  private let exceptionRules: Set<String>

  init(source: String) throws {
    guard source.utf8.count <= Self.maximumSourceBytes else {
      throw PublicSuffixDatabaseError.resourceLimitExceeded
    }

    var exact: Set<String> = []
    var wildcard: Set<String> = []
    var exceptions: Set<String> = []
    var ruleCount = 0

    for rawLine in source.split(whereSeparator: \Character.isNewline) {
      let line = rawLine.trimmingCharacters(in: .whitespaces)
      guard !line.isEmpty, !line.hasPrefix("//") else {
        continue
      }
      guard line.utf8.count <= Self.maximumRuleBytes else {
        throw PublicSuffixDatabaseError.resourceLimitExceeded
      }

      let destination: RuleDestination
      let unprefixed: Substring
      if line.hasPrefix("!") {
        destination = .exception
        unprefixed = line.dropFirst()
      } else if line.hasPrefix("*.") {
        destination = .wildcard
        unprefixed = line.dropFirst(2)
      } else {
        destination = .exact
        unprefixed = line[...]
      }

      let canonical = try Self.canonicalASCIIHost(String(unprefixed))
      switch destination {
      case .exact:
        guard exact.insert(canonical).inserted else {
          throw PublicSuffixDatabaseError.invalidRule
        }
      case .wildcard:
        guard wildcard.insert(canonical).inserted else {
          throw PublicSuffixDatabaseError.invalidRule
        }
      case .exception:
        guard exceptions.insert(canonical).inserted else {
          throw PublicSuffixDatabaseError.invalidRule
        }
      }

      ruleCount += 1
      guard ruleCount <= Self.maximumRuleCount else {
        throw PublicSuffixDatabaseError.resourceLimitExceeded
      }
    }

    guard !exact.isEmpty else {
      throw PublicSuffixDatabaseError.invalidRule
    }
    exactRules = exact
    wildcardRules = wildcard
    exceptionRules = exceptions
  }

  static func bundled() throws -> PublicSuffixDatabase {
    try bundledResult.get()
  }

  func publicSuffix(for canonicalASCIIHost: String) -> String? {
    let labels = canonicalASCIIHost.split(separator: ".", omittingEmptySubsequences: false)
    guard !labels.isEmpty, labels.allSatisfy({ !$0.isEmpty }) else {
      return nil
    }

    var longestException: Int?
    for index in labels.indices {
      let candidate = labels[index...].joined(separator: ".")
      if exceptionRules.contains(candidate) {
        let count = labels.count - index
        if count > (longestException ?? 0) {
          longestException = count
        }
      }
    }
    if let exceptionCount = longestException, exceptionCount > 1 {
      return labels.suffix(exceptionCount - 1).joined(separator: ".")
    }

    var matchingRuleLabels = 1  // The prevailing default rule is `*`.
    for index in labels.indices {
      let candidate = labels[index...].joined(separator: ".")
      if exactRules.contains(candidate) {
        matchingRuleLabels = max(matchingRuleLabels, labels.count - index)
      }
      if index > labels.startIndex, wildcardRules.contains(candidate) {
        matchingRuleLabels = max(matchingRuleLabels, labels.count - index + 1)
      }
    }

    guard matchingRuleLabels <= labels.count else {
      return nil
    }
    return labels.suffix(matchingRuleLabels).joined(separator: ".")
  }

  func registrableDomain(for canonicalASCIIHost: String) -> String? {
    guard let suffix = publicSuffix(for: canonicalASCIIHost) else {
      return nil
    }
    let hostLabels = canonicalASCIIHost.split(separator: ".")
    let suffixLabels = suffix.split(separator: ".")
    guard hostLabels.count > suffixLabels.count else {
      return nil
    }
    return hostLabels.suffix(suffixLabels.count + 1).joined(separator: ".")
  }

  private static let bundledResult: Result<PublicSuffixDatabase, any Error> = Result {
    guard
      let url = Bundle.module.url(
        forResource: "effective_tld_names",
        withExtension: "dat"
      )
    else {
      throw PublicSuffixDatabaseError.resourceUnavailable
    }
    let data = try Data(contentsOf: url, options: [.mappedIfSafe])
    guard data.count <= maximumSourceBytes else {
      throw PublicSuffixDatabaseError.resourceLimitExceeded
    }
    guard let source = String(data: data, encoding: .utf8) else {
      throw PublicSuffixDatabaseError.invalidEncoding
    }
    return try PublicSuffixDatabase(source: source)
  }

  private enum RuleDestination {
    case exact
    case wildcard
    case exception
  }

  private static func canonicalASCIIHost(_ input: String) throws -> String {
    guard !input.isEmpty,
      let url = WebURL("https://\(input)/"),
      url.scheme == "https",
      url.username == nil,
      url.password == nil,
      url.port == nil,
      url.path == "/",
      url.query == nil,
      url.fragment == nil,
      let host = url.hostname,
      !host.isEmpty,
      !host.hasSuffix(".")
    else {
      throw PublicSuffixDatabaseError.invalidRule
    }
    return host
  }
}
