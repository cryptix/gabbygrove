var ssbKeys = require('ssb-keys')
var tape = require('tape')
var gabby = require('..')

tape("make event", (t) => {
    const kp = ssbKeys.generate()


    setTimeout(() => {
        t.true(gabby.ready(), 'pb not initialized')

        var c1 = {
            type: 'test',
            i: 0,
        }

        let evt1 = gabby.makeEvent(kp, 1, null, c1)
        t.notEqual(evt1.key, '', 'has a key')
        t.equal(evt1.transfer.signature.length, 64, 'has 64bytes of sig')

        try {
            let tr1 = gabby.verifyTransfer(evt1.trBytes)
            t.ok(tr1, 'verfied 1')
        } catch (error) {
            t.error(error)
            t.end()
            return
        }

        var c2 = {
            type: 'test',
            i: 1,
        }

        let evt2 = gabby.makeEvent(kp, 2, evt1.key, c2)
        t.equal(evt2.event.previous, evt1.key, 'previous is key of evt1')

        try {
            let tr2 = gabby.verifyTransfer(evt2.trBytes)
            t.ok(tr2, 'verified 2')
        } catch (error) {
            t.error(error)
            t.end()
            return
        }


        t.end()
    }, 500) // wait for pb to load... :-/
})