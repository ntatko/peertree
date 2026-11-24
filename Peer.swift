import CryptoKit
import Foundation
import Network
import Security

private let serviceType = "_peertree-v2._tcp"
private let maxArchive: UInt64 = 512 * 1024 * 1024
private let maxInventory = 512 * 1024
private let chunkSize = 128 * 1024

struct Bootstrap: Decodable {
    let identity: String
    let name: String
    let directory: String
}

private struct IdentityMaterial: Decodable {
    let key: String
    let certificate: Data
}

func loadIdentity(_ config: Bootstrap) throws -> sec_identity_t {
    let data = try Data(contentsOf: URL(fileURLWithPath: config.identity))
    let material = try JSONDecoder().decode(IdentityMaterial.self, from: data)
    let key = try P256.Signing.PrivateKey(pemRepresentation: material.key)
    let attributes = [kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
                      kSecAttrKeyClass: kSecAttrKeyClassPrivate] as CFDictionary
    var error: Unmanaged<CFError>?
    guard let privateKey = SecKeyCreateWithData(key.x963Representation as CFData, attributes, &error),
          let certificate = SecCertificateCreateWithData(nil, material.certificate as CFData),
          let certifiedKey = SecCertificateCopyKey(certificate),
          let certifiedPoint = SecKeyCopyExternalRepresentation(certifiedKey, nil),
          certifiedPoint as Data == key.publicKey.x963Representation,
          let identity = SecIdentityCreate(nil, certificate, privateKey),
          let wrapped = sec_identity_create(identity) else {
        if let error { throw error.takeRetainedValue() }
        throw NSError(domain: NSOSStatusErrorDomain, code: Int(errSecInvalidItemRef), userInfo: [
            NSLocalizedDescriptionKey: "Could not load the nearby client identity."
        ])
    }
    return wrapped
}

func certificatePin(_ certificate: SecCertificate) -> String {
    SHA256.hash(data: SecCertificateCopyData(certificate) as Data)
        .map { String(format: "%02x", $0) }.joined()
}

// One encrypted connection carries one ZIP, or a zero-length presence probe.
final class Transfer {
    private let connection: NWConnection
    private let queue: DispatchQueue
    private let finished: (Bool) -> Void
    private var file: FileHandle?
    private var scratch: URL?
    private var didFinish = false

    init(_ connection: NWConnection, queue: DispatchQueue, finished: @escaping (Bool) -> Void) {
        self.connection = connection
        self.queue = queue
        self.finished = finished
    }

    private func start(_ ready: @escaping () -> Void) {
        connection.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready: ready()
            case .failed, .cancelled: self.finish(false)
            default: break
            }
        }
        queue.asyncAfter(deadline: .now() + .seconds(180)) { [weak self] in self?.finish(false) }
        connection.start(queue: queue)
    }

    private func finish(_ success: Bool) {
        guard !didFinish else { return }
        didFinish = true
        connection.stateUpdateHandler = nil
        connection.cancel()
        try? file?.close()
        if let scratch { try? FileManager.default.removeItem(at: scratch) }
        finished(success)
    }

    private func send(_ bytes: Data, then next: @escaping () -> Void) {
        connection.send(content: bytes, completion: .contentProcessed { [weak self] error in
            guard let self, !self.didFinish else { return }
            if error == nil { next() } else { self.finish(false) }
        })
    }

    private func read(_ count: Int, then next: @escaping (Data) -> Void) {
        connection.receive(minimumIncompleteLength: count, maximumLength: count) {
            [weak self] data, _, _, error in
            guard let self, !self.didFinish else { return }
            guard error == nil, let data, data.count == count else { self.finish(false); return }
            next(data)
        }
    }

    func upload(_ archive: URL?, recordInventory: @escaping (Data) -> Void) {
        start { [weak self] in
            guard let self else { return }
            do {
                var length: UInt64 = 0
                if let archive {
                    let handle = try FileHandle(forReadingFrom: archive)
                    self.file = handle
                    length = try handle.seekToEnd()
                    guard length > 0, length <= maxArchive else { self.finish(false); return }
                    try handle.seek(toOffset: 0)
                }
                let header = withUnsafeBytes(of: length.bigEndian) { Data($0) }
                self.send(header) { self.uploadChunk(length, recordInventory: recordInventory) }
            } catch { self.finish(false) }
        }
    }

    private func uploadChunk(_ remaining: UInt64, recordInventory: @escaping (Data) -> Void) {
        guard remaining > 0 else {
            read(5) { reply in
                let length = reply.dropFirst().reduce(0) { ($0 << 8) | Int($1) }
                guard reply.first == 1, length > 0, length <= maxInventory else {
                    self.finish(false)
                    return
                }
                self.read(length) { inventory in
                    recordInventory(inventory)
                    self.finish(true)
                }
            }
            return
        }
        do {
            let count = Int(min(remaining, UInt64(chunkSize)))
            guard let bytes = try file?.read(upToCount: count), bytes.count == count else {
                finish(false)
                return
            }
            send(bytes) { self.uploadChunk(remaining - UInt64(count), recordInventory: recordInventory) }
        } catch { finish(false) }
    }

    func download(to folder: URL, inventory: URL) {
        start { [weak self] in
            guard let self else { return }
            self.read(8) { data in
                let length = data.reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
                guard length <= maxArchive else { self.finish(false); return }
                if length == 0 {
                    self.reply(with: inventory)
                    return
                }
                let partial = folder.appendingPathComponent(UUID().uuidString).appendingPathExtension("partial")
                self.scratch = partial
                guard FileManager.default.createFile(atPath: partial.path, contents: nil) else {
                    self.finish(false)
                    return
                }
                do {
                    self.file = try FileHandle(forWritingTo: partial)
                    self.downloadChunk(length, to: partial.deletingPathExtension().appendingPathExtension("zip"),
                                       inventory: inventory)
                } catch { self.finish(false) }
            }
        }
    }

    private func reply(with inventory: URL) {
        let data = (try? Data(contentsOf: inventory)) ?? Data("[]".utf8)
        guard !data.isEmpty, data.count <= maxInventory else { finish(false); return }
        var reply = Data([1])
        reply.append(withUnsafeBytes(of: UInt32(data.count).bigEndian) { Data($0) })
        reply.append(data)
        send(reply) { self.finish(true) }
    }

    private func downloadChunk(_ remaining: UInt64, to archive: URL, inventory: URL) {
        guard remaining > 0 else {
            do {
                try file?.close()
                file = nil
                guard let scratch else { finish(false); return }
                try FileManager.default.moveItem(at: scratch, to: archive)
                self.scratch = nil
                reply(with: inventory)
            } catch { finish(false) }
            return
        }
        let count = Int(min(remaining, UInt64(chunkSize)))
        read(count) { data in
            do {
                try self.file?.write(contentsOf: data)
                self.downloadChunk(remaining - UInt64(data.count), to: archive, inventory: inventory)
            } catch { self.finish(false) }
        }
    }
}

final class Nearby {
    private let config: Bootstrap
    private let identity: sec_identity_t
    private let directory: URL
    private let queue = DispatchQueue(label: "neighbor-review.peer")
    private let timer: DispatchSourceTimer
    private var listener: NWListener?
    private var browser: NWBrowser?
    private var pins: [String: String] = [:]
    private var endpoints: [String: NWEndpoint] = [:]
    private var incoming: [UUID: Transfer] = [:]
    private var outgoing: [String: Transfer] = [:]
    private var attempted: [String: Date] = [:]
    private var syncRequest: String?
    private var reached: [String: Date] = [:]
    private var issues: [String: String] = [:]
    private var nextStart: [String: Date] = [:]
    private var backoff: [String: Double] = [:]

    init(_ config: Bootstrap) throws {
        self.config = config
        self.identity = try loadIdentity(config)
        self.directory = URL(fileURLWithPath: config.directory, isDirectory: true)
        self.timer = DispatchSource.makeTimerSource(queue: queue)
    }

    private func parameters(for destination: String? = nil) -> NWParameters {
        let options = NWProtocolTLS.Options()
        let security = options.securityProtocolOptions
        sec_protocol_options_set_min_tls_protocol_version(security, .TLSv13)
        sec_protocol_options_set_tls_resumption_enabled(security, false)
        sec_protocol_options_set_tls_tickets_enabled(security, false)
        sec_protocol_options_set_local_identity(security, identity)
        sec_protocol_options_set_peer_authentication_required(security, true)
        sec_protocol_options_set_verify_block(security, { [weak self] metadata, token, complete in
            guard let self else { complete(false); return }
            var leaf: SecCertificate?
            _ = sec_protocol_metadata_access_peer_certificate_chain(metadata) { certificate in
                if leaf == nil { leaf = sec_certificate_copy_ref(certificate).takeRetainedValue() }
            }
            if leaf == nil {
                let trust = sec_trust_copy_ref(token).takeRetainedValue()
                leaf = (SecTrustCopyCertificateChain(trust) as? [SecCertificate])?.first
            }
            guard let leaf else {
                complete(false)
                return
            }
            let pin = certificatePin(leaf)
            if let destination { complete(self.pins[destination] == pin) }
            else { complete(self.pins.values.contains(pin)) }
        }, queue)
        let settings = NWParameters(tls: options, tcp: NWProtocolTCP.Options())
        settings.includePeerToPeer = true
        settings.acceptLocalOnly = true
        return settings
    }

    func start() {
        timer.schedule(deadline: .now(), repeating: .seconds(2))
        timer.setEventHandler { [weak self] in self?.tick() }
        timer.resume()
    }

    private func retry(_ service: String, because issue: Error) {
        let delay = backoff[service] ?? 2
        backoff[service] = min(delay * 2, 60)
        nextStart[service] = Date().addingTimeInterval(delay)
        issues[service] = String(describing: issue)
    }

    private func ensureListener() {
        guard listener == nil, nextStart["advertising", default: .distantPast] <= Date() else { return }
        do {
            let service = try NWListener(using: parameters())
            service.service = NWListener.Service(name: config.name, type: serviceType)
            service.newConnectionHandler = { [weak self] connection in self?.receive(connection) }
            service.stateUpdateHandler = { [weak self] state in
                guard let self else { return }
                switch state {
                case .ready: self.issues.removeValue(forKey: "advertising")
                case .waiting(let error): self.issues["advertising"] = String(describing: error)
                case .failed(let error):
                    self.listener?.cancel()
                    self.listener = nil
                    self.retry("advertising", because: error)
                default: break
                }
            }
            listener = service
            service.start(queue: queue)
        } catch { retry("advertising", because: error) }
    }

    private func ensureBrowser() {
        guard browser == nil, nextStart["discovery", default: .distantPast] <= Date() else { return }
        let options = NWParameters()
        options.includePeerToPeer = true
        let service = NWBrowser(for: .bonjour(type: serviceType, domain: nil), using: options)
        service.browseResultsChangedHandler = { [weak self] results, _ in
            guard let self else { return }
            var found: [String: NWEndpoint] = [:]
            for result in results {
                if case .service(let name, _, _, _) = result.endpoint, name != self.config.name {
                    found[name] = result.endpoint
                }
            }
            for name in self.endpoints.keys where found[name] == nil {
                self.attempted.removeValue(forKey: name)
            }
            self.endpoints = found
        }
        service.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready: self.issues.removeValue(forKey: "discovery")
            case .waiting(let error): self.issues["discovery"] = String(describing: error)
            case .failed(let error):
                self.browser?.cancel()
                self.browser = nil
                self.endpoints = [:]
                self.retry("discovery", because: error)
            default: break
            }
        }
        browser = service
        service.start(queue: queue)
    }

    private func receive(_ connection: NWConnection) {
        guard !pins.isEmpty, incoming.count < 6 else { connection.cancel(); return }
        let transferID = UUID()
        let transfer = Transfer(connection, queue: queue) { [weak self] _ in
            self?.incoming.removeValue(forKey: transferID)
        }
        incoming[transferID] = transfer
        transfer.download(to: directory.appendingPathComponent("incoming", isDirectory: true),
                          inventory: directory.appendingPathComponent("inventory.json"))
    }

    private func send(to name: String, at endpoint: NWEndpoint, archive: URL?) {
        let connection = NWConnection(to: endpoint, using: parameters(for: name))
        let transfer = Transfer(connection, queue: queue) { [weak self] success in
            guard let self else { return }
            self.outgoing.removeValue(forKey: name)
            if success {
                self.reached[name] = Date()
            }
        }
        outgoing[name] = transfer
        attempted[name] = Date()
        transfer.upload(archive) { [weak self] inventory in
            guard let self else { return }
            let path = self.directory.appendingPathComponent("inventories", isDirectory: true)
                .appendingPathComponent(name).appendingPathExtension("json")
            try? inventory.write(to: path, options: .atomic)
        }
    }

    private func readJSON<T: Decodable>(_ name: String, as type: T.Type) -> T? {
        guard let data = try? Data(contentsOf: directory.appendingPathComponent(name)) else { return nil }
        return try? JSONDecoder().decode(type, from: data)
    }

    private func tick() {
        if let requested = readJSON("sync.json", as: String.self), requested != syncRequest {
            syncRequest = requested
            attempted.removeAll()
        }
        let configuredPins = readJSON("peers.json", as: [String: String].self) ?? [:]
        for name in Set(pins.keys).union(configuredPins.keys) where pins[name] != configuredPins[name] {
            attempted.removeValue(forKey: name)
            reached.removeValue(forKey: name)
        }
        pins = configuredPins
        ensureListener()
        ensureBrowser()
        let files = readJSON("exports.json", as: [String: String].self) ?? [:]
        let now = Date()
        for (name, endpoint) in endpoints where pins[name] != nil && outgoing[name] == nil {
            let file = files[name]
            let sinceAttempt = now.timeIntervalSince(attempted[name] ?? .distantPast)
            if (file != nil && sinceAttempt >= 6) || sinceAttempt >= 20 {
                let archive = file.map {
                    directory.appendingPathComponent("outgoing", isDirectory: true).appendingPathComponent($0)
                }
                send(to: name, at: endpoint, archive: archive)
            }
        }
        let online = reached.keys.filter {
            pins[$0] != nil && endpoints[$0] != nil && now.timeIntervalSince(reached[$0] ?? .distantPast) < 35
        }.sorted()
        let status: [String: Any] = ["online": online, "error": issues.values.sorted().joined(separator: " · ")]
        if let data = try? JSONSerialization.data(withJSONObject: status) {
            try? data.write(to: directory.appendingPathComponent("status.json"), options: .atomic)
        }
    }
}

@available(macOS 15.0, *)
func main() throws {
    let checking = CommandLine.arguments.count == 3 && CommandLine.arguments[1] == "--check-identity"
    if !checking && CommandLine.arguments.count != 2 {
        throw NSError(domain: "PeerTree", code: 1, userInfo: [
            NSLocalizedDescriptionKey: "The nearby Wi-Fi helper expects one bootstrap file."
        ])
    }
    let data = try Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[checking ? 2 : 1]))
    let config = try JSONDecoder().decode(Bootstrap.self, from: data)
    if checking {
        let wrapper = try loadIdentity(config)
        guard let local = sec_identity_copy_ref(wrapper)?.takeRetainedValue() else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(errSecInvalidItemRef))
        }
        var certificate: SecCertificate?
        let status = SecIdentityCopyCertificate(local, &certificate)
        guard status == errSecSuccess, let certificate else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status))
        }
        print(certificatePin(certificate))
        return
    }
    let nearby = try Nearby(config)
    nearby.start()
    withExtendedLifetime(nearby) { dispatchMain() }
}

do { try main() } catch {
    FileHandle.standardError.write(Data((error.localizedDescription + "\n").utf8))
    exit(1)
}
