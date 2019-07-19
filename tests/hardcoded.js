var ssbKeys = require('ssb-keys')
var tape = require('tape')
var gabby = require('..')

// convertOpts defines how to press the values in javascripts type system
var convertOpts = {
    longs: Number,
    enums: String, // could be easier to deal with numbers and maps for them
    bytes: Buffer, // alternative is base64 string but we want the actual bytes most of the time
}

tape("hardcoded", (t) => {

    var protobuf = require('protobufjs')
    protobuf.load("message.proto", function (err, root) {
        if (err) throw err;

        // Obtain a message type
        var event = root.lookupType("gabbygrove.Event");

        // Create a new message
        var evt1 = {
            sequence: 42,
            timestamp: 0,
            content: {
                type: 1,
            }
        }
        var pbEvent = event.create(evt1); // or use .fromObject if conversion is necessary

        var buffer = event.encode(pbEvent).finish();
        console.log("evt1:", buffer.toString('base64'))

        // create an event from raw bytes
        var decodedEvt = event.decode(buffer);

        var object = event.toObject(decodedEvt, convertOpts);
        console.log("evt1 to obj:")
        console.log(object)

        // example from Writer go test:
        var input = Buffer.from("122101aed3dab65ce9e0d6c50d46fceffb552296ed21b6e0b537a6a0184575ce8f5cbd2227080110071a2103e806ecf2b7c37fb06dc198a9b905be64ee3fdb8237ef80d316acb7c85bbf5f02", "hex")
        var evt2 = event.decode(input)

        var err = event.verify(evt2)
        if (err) throw err

        var obj2 = event.toObject(evt2, convertOpts);
        // console.log("evt2 from b64 data:")
        // console.log(obj2)

        if (obj2.author.length !== 33) throw new Error("invalid reference length")
        if (obj2.author[0] !== 0x01) throw new Error("not ed25519 ref type")
        var msgAuthor = obj2.author.slice(1)

        // generate key-pair with same seed
        var seed = Buffer.from("dead".repeat(8))
        var testKp = ssbKeys.generate('ed25519', seed)

        var pubBytes = Buffer.from(testKp.public.replace(/\.ed25519$/, ''), 'base64')

        t.true(msgAuthor.equals(pubBytes), "right test keypair")

        // from go test, msg3 (type:contact spectating:true)
        var trBuf = Buffer.from("0a710a2102bb4ba82ee4180789b937080bd995d00966f3a13bf35785c2af51f480fbcb1cdf1221018a35dfa466b23c247f957d71504c01074653df6a6a831108d015ea894b192203180422270801102a1a210388feb52df7ad32786e8c1e527a75b9b2ad71445752a18eb25481dfc98445422f124071e1eed9f315fcb708bd08cdc86a2e5b2324ad6485979ff81e5390358f83a4ff8da3f5d7fa9f0f3174d6a2bbeeac02746e3372a6ec81e80b0a3aca4bf667c90b1a2a7b22736571223a322c2273706563746174696e67223a747275652c2274797065223a2274657374227d0a", 'hex')

        // throws on invalid
        var event
        try {
            event = gabby.verifyTransfer(trBuf)
        } catch (e) {
            t.error(e)
            t.end()
            return
        }
        // console.dir(event)
        t.equal(event.content.seq, 2)
        t.equal(event.content.type, 'test')
        t.equal(event.content.spectating, true)
        t.end()
    })

})