const EventEmitter = require('events').EventEmitter
    , inherits     = require('util').inherits
    , bl           = require('bl')


function create (options) {
  if (typeof options != 'object')
    throw new TypeError('must provide an options object')

  if (typeof options.path != 'string')
    throw new TypeError('must provide a \'path\' option')

  if (typeof options.secret != 'string')
    throw new TypeError('must provide a \'secret\' option')

  // make it an EventEmitter, sort of
  handler.__proto__ = EventEmitter.prototype
  EventEmitter.call(handler)

  return handler


  function handler (req, res, callback) {
    if (req.url.split('?').shift() !== options.path)
      return callback()

    function hasError (msg) {
      res.writeHead(400, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ error: msg }))

      var err = new Error(msg)

      handler.emit('error', err, req)
      callback(err)
    }

    req.pipe(bl(function (err, data) {
      if (err) {
        return hasError(err.message)
      }

      var obj
        ,event
        ,id

      try {
        obj = JSON.parse(data.toString())
        event=obj.hook_name
        id=obj.push_data.after

        if (!obj.password||obj.password !== options.secret)
        return hasError('secret does not match blob signature')

      } catch (e) {
        return hasError(e)
      }

      res.writeHead(200, { 'content-type': 'application/json' })
      res.end('{"ok":true}')

      var emitData = {
          event   : event
        , id      : id
        , payload : obj
        , protocol: req.protocol
        , host    : req.headers['host']
        , url     : req.url
      }

      handler.emit(event, emitData)
      handler.emit('*', emitData)
    }))
  }
}


module.exports = create
