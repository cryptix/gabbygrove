var ssbKeys = require('ssb-keys')
var protobuf = require('protobufjs')

// ssb-keys only exports signObj and verifyObj so we use sodium directly
var sodium = require('sodium-native')

// uninitialized
var typeEvent = null
var typeTransfer = null

// not sure if there is a callback-less way?
protobuf.load("message.proto", function (err, root) {
    if (err) throw err;

    // load the message types
    typeEvent = root.lookupType("gabbygrove.Event");
    typeTransfer = root.lookupType("gabbygrove.Transfer");

    console.warn('protobuf definitions loaded')
})

exports.ready = () => {
    return typeEvent !== null
}

// convertOpts defines how to press the values in javascripts type system
var convertOpts = {
    longs: Number,
    enums: String, // could be easier to deal with numbers and maps for them
    bytes: Buffer, // alternative is base64 string but we want the actual bytes most of the time
}

/* verify transfer checks the content was signed by the author of the event
*/
function verifyTransfer (trBuf) {
    if (typeTransfer == null) throw new Error('gabbygrove: protobf uninitialized')

    // decode Buffer to protobuf object
    var transferMsg = typeTransfer.decode(trBuf)

    // verify structure (enum values etc)
    var err = typeTransfer.verify(transferMsg)
    if (err) throw err

    // compare content hash
    var computedHash = binrefContentHash(transferMsg.content)

    // decode event from transfer (for content hash and author)
    var evtFromTr = typeEvent.decode(transferMsg.event)

    // TODO: check content.hash[0] is right RefType enum value
    var sentHash = evtFromTr.content.hash

    if (!computedHash.equals(sentHash)) throw new Error('gabbygrove: content hash comprassion failed')

    // TODO: check author[0] is right RefType enum value
    var authorPubKey = evtFromTr.author.slice(1)

    if (transferMsg.signature.length !== 64) throw new Error('gabbygrove: expected 64 bytes signature')

    var verified = sodium.crypto_sign_verify_detached(transferMsg.signature, transferMsg.event, authorPubKey)
    if (!verified) throw new Error('gabbygrove: signature verification failed')

    // might want to return the deocdec transfer to store it, just a demo

    return {
        key: binrefMessageHash(Buffer.concat([
            transferMsg.event,
            transferMsg.signature,
        ])),
        evt: typeEvent.toObject(evtFromTr, convertOpts),
        content: JSON.parse(transferMsg.content)
    }
}

exports.verifyTransferSync = verifyTransfer
exports.verifyTransfer = (trBuf, cb) => {
    try {
        let evt = verifyTransfer(trBuf)
        cb(null, evt)
    } catch (error) {
        cb(error)
    }
}

// very bad chain maker
function makeEvent (keyPair, sequence, prev, content) {
    if (typeEvent == null) throw new Error('gabbygrove: protobf uninitialized')

    let jsonBufContent = Buffer.from(JSON.stringify(content), 'binary')

    // fill event fields
    let event = {
        author: binrefAuthor(keyPair.public),
        sequence: sequence,
        content: {
            type: 2, // JSON enum value
            size: jsonBufContent.length,
            hash: binrefContentHash(jsonBufContent),
        },
        timestamp: Date.now() / 1000,
    }
    if (sequence > 1 && prev === null) throw new Error('seq > 1! must have previous')
    if (sequence > 1) {
        event.previous = prev
    }

    // encode event to buffer
    let pbEvent = typeEvent.create(event)
    let evtBuf = typeEvent.encode(pbEvent).finish();

    // sign evtBuf with passed keypair
    let signature = Buffer.alloc(sodium.crypto_sign_BYTES)
    let secret = Buffer.from(keyPair.private.replace(/\.ed25519$/, ''), 'base64')
    sodium.crypto_sign_detached(signature, evtBuf, secret)

    // compute hash of the signed event
    let key = binrefMessageHash(Buffer.concat([
        evtBuf,
        signature,
    ]))

    // fill transfer fields
    let transfer = {
        event: evtBuf,
        signature: signature,
        content: jsonBufContent,
    }

    let pbTransfer = typeTransfer.create(transfer)

    return {
        key: key,
        event: pbEvent,
        transfer: pbTransfer, // not sure if needed
        trBytes: typeTransfer.encode(pbTransfer).finish()
    }
}
exports.makeEventSync = makeEvent
exports.makeEvent = ({keyPair, sequence, prev, content}, cb) => {
    try {
        let newMsg = makeEvent(keyPair, sequence, prev, content)
        cb(null, newMsg)
    } catch (error) {
        console.warn(err)
        cb(error)
    }
}

function binrefAuthor(ssbPubKey) {
    let tipe = Buffer.alloc(1)
    tipe.writeInt8(1)
    return Buffer.concat([
        tipe,
        Buffer.from(ssbPubKey.replace(/\.ed25519$/, ''), 'base64')
    ])
}

function binrefMessageHash(content) {
    let buf = Buffer.alloc(32)
    sodium.crypto_hash_sha256(buf, content)
    let tipe = Buffer.alloc(1)
    tipe.writeInt8(2)
    return Buffer.concat([
        tipe,
        buf
    ])
}

function binrefContentHash(content) {
    let buf = Buffer.alloc(32)
    sodium.crypto_hash_sha256(buf, content)
    let tipe = Buffer.alloc(1)
    tipe.writeInt8(3)
    return Buffer.concat([
        tipe,
        buf
    ])
}
