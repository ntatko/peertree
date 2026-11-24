import CryptoKit
import Foundation
import Network
import Security

private let serviceType = "_peertree-v2._tcp"
private let maxArchive: UInt64 = 512 * 1024 * 1024
// Inventories travel in packets so large record histories never need one huge read.
private let maxPacket = 512 * 1024
private let maxInventory = 64 * 1024 * 1024
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
    private var inventory = Data()

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
                let value = reply.dropFirst().reduce(0) { ($0 << 8) | Int($1) }
                switch reply.first {
                case 1 where value > 0 && value <= maxPacket:
                    self.read(value) { inventory in
                        recordInventory(inventory)
                        self.finish(true)
                    }
                case 2 where value > 1 && value <= maxInventory / maxPacket:
                    self.readPackets(value, recordInventory: recordInventory)
                default:
                    self.finish(false)
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

    private func readPackets(_ remaining: Int, recordInventory: @escaping (Data) -> Void) {
        guard remaining > 0 else {
            recordInventory(inventory)
            finish(true)
            return
        }
        read(4) { header in
            let length = header.reduce(0) { ($0 << 8) | Int($1) }
            guard length > 0, length <= maxPacket, self.inventory.count + length <= maxInventory else {
                self.finish(false)
                return
            }
            self.read(length) { packet in
                self.inventory.append(packet)
                self.readPackets(remaining - 1, recordInventory: recordInventory)
            }
        }
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
        // A single-packet inventory keeps the 0.5.0 reply, so those peers still sync.
        if data.count <= maxPacket {
            var reply = Data([1])
            reply.append(withUnsafeBytes(of: UInt32(data.count).bigEndian) { Data($0) })
            reply.append(data)
            send(reply) { self.finish(true) }
            return
        }
        let packets = stride(from: 0, to: data.count, by: maxPacket).map {
            data.subdata(in: $0..<min($0 + maxPacket, data.count))
        }
        var header = Data([2])
        header.append(withUnsafeBytes(of: UInt32(packets.count).bigEndian) { Data($0) })
        send(header) { self.sendPackets(packets[...]) }
    }

    private func sendPackets(_ packets: ArraySlice<Data>) {
        guard let packet = packets.first else { finish(true); return }
        var framed = withUnsafeBytes(of: UInt32(packet.count).bigEndian) { Data($0) }
        framed.append(packet)
        send(framed) { self.sendPackets(packets.dropFirst()) }
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

private let joinServiceType = "_peertree-join._tcp"
private let maxPairingFrame = 256 * 1024

private func hex(_ bytes: some Sequence<UInt8>) -> String {
    bytes.map { String(format: "%02x", $0) }.joined()
}

private func randomBytes(_ count: Int) -> Data {
    var bytes = Data(count: count)
    _ = bytes.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!) }
    return bytes
}

private func peerPin(_ connection: NWConnection) -> String? {
    guard let metadata = connection.metadata(definition: NWProtocolTLS.definition) as? NWProtocolTLS.Metadata
    else { return nil }
    var leaf: SecCertificate?
    _ = sec_protocol_metadata_access_peer_certificate_chain(metadata.securityProtocolMetadata) { certificate in
        if leaf == nil { leaf = sec_certificate_copy_ref(certificate).takeRetainedValue() }
    }
    return leaf.map(certificatePin)
}

private func ownPin(_ identity: sec_identity_t) -> String {
    guard let local = sec_identity_copy_ref(identity)?.takeRetainedValue() else { return "" }
    var certificate: SecCertificate?
    guard SecIdentityCopyCertificate(local, &certificate) == errSecSuccess, let certificate else { return "" }
    return certificatePin(certificate)
}

// TLS between unpaired Macs encrypts the channel but proves nothing about who is on the
// other end. Both people check a six-digit code instead: it covers both certificates and a
// random value from each side, and the joining Mac commits to its value first, so a device in
// the middle cannot steer both connections to the same code.
final class PairingSession {
    let id = UUID().uuidString
    let role: String
    private let connection: NWConnection
    private let queue: DispatchQueue
    private let localPin: String
    private let report: (PairingSession) -> Void
    private let ended: (PairingSession) -> Void
    private let nonce = randomBytes(32)
    private var commitment: Data?
    private var buffer = Data()
    private var localOffer: Any?
    private var remoteOffer: Any?
    private var finished = false
    private(set) var state = "connecting"
    private(set) var code = ""
    private(set) var remotePin = ""
    private(set) var error = ""
    let peerName: String

    init(role: String, connection: NWConnection, peerName: String, localPin: String, queue: DispatchQueue,
         report: @escaping (PairingSession) -> Void, ended: @escaping (PairingSession) -> Void) {
        self.role = role
        self.connection = connection
        self.peerName = peerName
        self.localPin = localPin
        self.queue = queue
        self.report = report
        self.ended = ended
    }

    var status: [String: Any] {
        ["session": id, "role": role, "state": state, "code": code, "peer": peerName, "error": error]
    }

    var result: [String: Any]? {
        guard state == "paired", let remoteOffer else { return nil }
        return ["session": id, "role": role, "pin": remotePin, "offer": remoteOffer]
    }

    func start() {
        connection.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready: self.ready()
            case .failed(let error): self.fail("The connection failed. \(error.localizedDescription)")
            case .cancelled: self.fail("The other Mac closed the connection.")
            default: break
            }
        }
        queue.asyncAfter(deadline: .now() + .seconds(300)) { [weak self] in
            self?.fail("Pairing timed out. Start again from the host.")
        }
        connection.start(queue: queue)
    }

    private func ready() {
        guard let pin = peerPin(connection), pin.count == 64 else {
            fail("The other Mac did not present a certificate.")
            return
        }
        remotePin = pin
        if role == "join" {
            send(["commit": hex(digest("commit", nonce))])
        }
        receive()
    }

    private var hostPin: String { role == "host" ? localPin : remotePin }
    private var joinPin: String { role == "join" ? localPin : remotePin }

    private func digest(_ label: String, _ parts: Data...) -> Data {
        var hasher = SHA256()
        hasher.update(data: Data("peertree-pair-\(label)\0\(hostPin)\0\(joinPin)\0".utf8))
        for part in parts { hasher.update(data: part) }
        return Data(hasher.finalize())
    }

    private func showCode(hostNonce: Data, joinNonce: Data) {
        let value = digest("code", hostNonce, joinNonce).prefix(8).reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
        code = String(format: "%06llu", value % 1_000_000)
        state = "verify"
        report(self)
    }

    func confirm(_ offer: Any) {
        guard state == "verify", localOffer == nil else { return }
        localOffer = offer
        state = "waiting"
        send(["confirm": offer])
        complete()
    }

    func cancel(_ reason: String) {
        guard !finished else { return }
        send(["cancel": reason])
        fail(reason)
    }

    private func complete() {
        guard localOffer != nil, remoteOffer != nil, !finished else {
            report(self)
            return
        }
        finished = true
        state = "paired"
        report(self)
        queue.asyncAfter(deadline: .now() + .seconds(2)) { [weak self] in
            guard let self else { return }
            self.connection.cancel()
            self.ended(self)
        }
    }

    private func fail(_ reason: String) {
        guard !finished else { return }
        finished = true
        state = "failed"
        error = reason
        connection.stateUpdateHandler = nil
        connection.cancel()
        report(self)
        ended(self)
    }

    private func handle(_ message: [String: Any]) {
        if let reason = message["cancel"] as? String {
            fail(reason.isEmpty ? "The other Mac cancelled pairing." : reason)
        } else if role == "host", commitment == nil, let value = message["commit"] as? String,
                  let data = Data(hexString: value), data.count == 32 {
            commitment = data
            send(["nonce": hex(nonce)])
        } else if role == "join", code.isEmpty, let value = message["nonce"] as? String,
                  let hostNonce = Data(hexString: value), hostNonce.count == 32 {
            send(["nonce": hex(nonce)])
            showCode(hostNonce: hostNonce, joinNonce: nonce)
        } else if role == "host", code.isEmpty, let commitment, let value = message["nonce"] as? String,
                  let joinNonce = Data(hexString: value), joinNonce.count == 32 {
            guard digest("commit", joinNonce) == commitment else {
                cancel("The other Mac's pairing values did not match its commitment.")
                return
            }
            showCode(hostNonce: nonce, joinNonce: joinNonce)
        } else if !code.isEmpty, remoteOffer == nil, let offer = message["confirm"] {
            remoteOffer = offer
            complete()
        } else {
            cancel("The other Mac sent an unexpected pairing message.")
        }
    }

    private func send(_ message: [String: Any]) {
        guard let body = try? JSONSerialization.data(withJSONObject: message) else { return }
        var frame = withUnsafeBytes(of: UInt32(body.count).bigEndian) { Data($0) }
        frame.append(body)
        connection.send(content: frame, completion: .contentProcessed { [weak self] error in
            if let error { self?.fail("Could not reach the other Mac. \(error.localizedDescription)") }
        })
    }

    private func receive() {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, done, error in
            guard let self, !self.finished else { return }
            if let data { self.buffer.append(data) }
            while self.buffer.count >= 4 {
                let length = self.buffer.prefix(4).reduce(0) { ($0 << 8) | Int($1) }
                guard length > 0, length <= maxPairingFrame else {
                    self.fail("The other Mac sent an oversized pairing message.")
                    return
                }
                guard self.buffer.count >= 4 + length else { break }
                let body = self.buffer.subdata(in: self.buffer.startIndex + 4..<self.buffer.startIndex + 4 + length)
                self.buffer.removeFirst(4 + length)
                guard let message = try? JSONSerialization.jsonObject(with: body) as? [String: Any] else {
                    self.fail("The other Mac sent an unreadable pairing message.")
                    return
                }
                self.handle(message)
                if self.finished { return }
            }
            if error != nil || done {
                if self.state != "paired" { self.fail("The other Mac closed the connection.") }
                return
            }
            self.receive()
        }
    }
}

extension Data {
    init?(hexString: String) {
        guard hexString.count % 2 == 0, hexString.allSatisfy(\.isHexDigit) else { return nil }
        var bytes = [UInt8]()
        var index = hexString.startIndex
        while index < hexString.endIndex {
            let next = hexString.index(index, offsetBy: 2)
            guard let byte = UInt8(hexString[index..<next], radix: 16) else { return nil }
            bytes.append(byte)
            index = next
        }
        self.init(bytes)
    }
}

// A joining Mac advertises on its own service while it waits; a host lists those Macs only
// while its Add a Teammate window is open. Python drives both through small JSON files.
final class Pairing {
    private let identity: sec_identity_t
    private let localPin: String
    private let name: String
    private let directory: URL
    private let queue: DispatchQueue
    private let timer: DispatchSourceTimer
    private var listener: NWListener?
    private var listenerName = ""
    private var browser: NWBrowser?
    private var requests: [String: (endpoint: NWEndpoint, name: String)] = [:]
    private var writtenRequests = Data()
    private var session: PairingSession?
    private var handledStart = ""
    private var handledConfirm = ""

    init(identity: sec_identity_t, name: String, directory: URL, queue: DispatchQueue) {
        self.identity = identity
        self.localPin = ownPin(identity)
        self.name = name
        self.directory = directory
        self.queue = queue
        self.timer = DispatchSource.makeTimerSource(queue: queue)
    }

    func start() {
        timer.schedule(deadline: .now(), repeating: .milliseconds(500))
        timer.setEventHandler { [weak self] in self?.tick() }
        timer.resume()
    }

    private func parameters() -> NWParameters {
        let options = NWProtocolTLS.Options()
        let security = options.securityProtocolOptions
        sec_protocol_options_set_min_tls_protocol_version(security, .TLSv13)
        sec_protocol_options_set_tls_resumption_enabled(security, false)
        sec_protocol_options_set_tls_tickets_enabled(security, false)
        sec_protocol_options_set_local_identity(security, identity)
        sec_protocol_options_set_peer_authentication_required(security, true)
        // Any certificate may connect here; the six-digit code authenticates the pairing.
        sec_protocol_options_set_verify_block(security, { _, _, complete in complete(true) }, queue)
        let settings = NWParameters(tls: options, tcp: NWProtocolTCP.Options())
        settings.includePeerToPeer = true
        settings.acceptLocalOnly = true
        return settings
    }

    private func read(_ name: String) -> [String: Any]? {
        guard let data = try? Data(contentsOf: directory.appendingPathComponent(name)) else { return nil }
        return (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
    }

    private func write(_ name: String, _ value: Any) {
        guard let data = try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]) else { return }
        try? data.write(to: directory.appendingPathComponent(name), options: .atomic)
    }

    private func tick() {
        let join = read("join.json")?["name"] as? String
        if let join, listener == nil || listenerName != join {
            startListener(join)
        } else if join == nil, let listener {
            listener.cancel()
            self.listener = nil
        }
        let hosting = read("host.json") != nil
        if hosting, browser == nil {
            startBrowser()
        } else if !hosting, let browser {
            browser.cancel()
            self.browser = nil
            requests = [:]
        }
        let listed = requests.map { ["id": $0.key, "name": $0.value.name] }
            .sorted { ($0["name"] ?? "") < ($1["name"] ?? "") }
        if let data = try? JSONSerialization.data(withJSONObject: listed, options: [.sortedKeys]),
           data != writtenRequests {
            writtenRequests = data
            try? data.write(to: directory.appendingPathComponent("requests.json"), options: .atomic)
        }
        if let start = read("pair-start.json"), let nonce = start["nonce"] as? String, nonce != handledStart,
           let target = start["id"] as? String {
            handledStart = nonce
            connect(to: target)
        }
        if let confirm = read("pair-confirm.json"), let id = confirm["session"] as? String,
           id != handledConfirm, let offer = confirm["offer"] {
            handledConfirm = id
            if session?.id == id { session?.confirm(offer) }
        }
        if let cancel = read("pair-cancel.json"), let id = cancel["session"] as? String, session?.id == id {
            session?.cancel("Pairing was cancelled on the other Mac.")
        }
    }

    private func startListener(_ display: String) {
        listener?.cancel()
        listenerName = display
        do {
            let service = try NWListener(using: parameters())
            service.service = NWListener.Service(name: name, type: joinServiceType, domain: nil,
                                                 txtRecord: NWTXTRecord(["name": String(display.prefix(80))]))
            service.newConnectionHandler = { [weak self] connection in
                guard let self, self.session == nil else { connection.cancel(); return }
                self.begin(role: "join", connection: connection, peerName: "")
            }
            service.stateUpdateHandler = { [weak self] state in
                if case .failed(let error) = state {
                    self?.write("pairing.json", ["state": "failed", "error": "Could not advertise this Mac. \(error)"])
                    self?.listener = nil
                }
            }
            listener = service
            service.start(queue: queue)
        } catch {
            write("pairing.json", ["state": "failed", "error": "Could not advertise this Mac. \(error)"])
        }
    }

    private func startBrowser() {
        let options = NWParameters()
        options.includePeerToPeer = true
        let service = NWBrowser(for: .bonjourWithTXTRecord(type: joinServiceType, domain: nil), using: options)
        service.browseResultsChangedHandler = { [weak self] results, _ in
            guard let self else { return }
            var found: [String: (endpoint: NWEndpoint, name: String)] = [:]
            for result in results {
                guard case .service(let id, _, _, _) = result.endpoint, id != self.name else { continue }
                var display = "Nearby Mac"
                if case .bonjour(let txt) = result.metadata, let value = txt["name"], !value.isEmpty {
                    display = value
                }
                found[id] = (result.endpoint, display)
            }
            self.requests = found
        }
        browser = service
        service.start(queue: queue)
    }

    private func connect(to target: String) {
        guard session == nil else { return }
        guard let request = requests[target] else {
            write("pairing.json", ["state": "failed", "error": "That Mac is no longer waiting to join."])
            return
        }
        begin(role: "host", connection: NWConnection(to: request.endpoint, using: parameters()),
              peerName: request.name)
    }

    private func begin(role: String, connection: NWConnection, peerName: String) {
        let created = PairingSession(role: role, connection: connection, peerName: peerName, localPin: localPin,
                                     queue: queue, report: { [weak self] session in
            self?.write("pairing.json", session.status)
            if let result = session.result { self?.write("pair-result.json", result) }
        }, ended: { [weak self] session in
            if self?.session === session { self?.session = nil }
        })
        session = created
        write("pairing.json", created.status)
        created.start()
    }
}

final class Nearby {
    private let config: Bootstrap
    private let identity: sec_identity_t
    private let directory: URL
    private let queue = DispatchQueue(label: "neighbor-review.peer")
    private let timer: DispatchSourceTimer
    private let pairing: Pairing
    private let parent = getppid()
    private var listener: NWListener?
    private var browser: NWBrowser?
    private var pins: [String: String] = [:]
    private var endpoints: [String: NWEndpoint] = [:]
    private var incoming: [UUID: Transfer] = [:]
    private var outgoing: [String: Transfer] = [:]
    private var attempted: [String: Date] = [:]
    private var syncRequest: String?
    private var reached: [String: Date] = [:]
    private var delivered: [String: (String, Date)] = [:]
    private var issues: [String: String] = [:]
    private var nextStart: [String: Date] = [:]
    private var backoff: [String: Double] = [:]

    init(_ config: Bootstrap) throws {
        self.config = config
        self.identity = try loadIdentity(config)
        self.directory = URL(fileURLWithPath: config.directory, isDirectory: true)
        self.timer = DispatchSource.makeTimerSource(queue: queue)
        self.pairing = Pairing(identity: identity, name: config.name, directory: directory, queue: queue)
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
        pairing.start()
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
                if let archive { self.delivered[name] = (archive.lastPathComponent, Date()) }
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
        // PeerTree's service owns this helper; stop advertising as soon as it is gone.
        if getppid() != parent { exit(0) }
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
            let sinceAttempt = now.timeIntervalSince(attempted[name] ?? .distantPast)
            // A delivered batch isn't sent again while the teammate imports it. Quick probes
            // fetch its updated inventory so the next batch follows; after a minute, resend.
            var file = files[name]
            var probeEvery = 20.0
            if let current = file, let (sent, at) = delivered[name], sent == current {
                let sinceDelivery = now.timeIntervalSince(at)
                if sinceDelivery < 60 { file = nil }
                if sinceDelivery < 120 { probeEvery = 6 }
            }
            if (file != nil && sinceAttempt >= 6) || sinceAttempt >= probeEvery {
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
