path     = require 'path'
loopback = require "#{path.join process.cwd(), 'node_modules', 'loopback'}"

hasAccessToken = (req)->
  req.hasOwnProperty('accessToken') and req.accessToken?
module.exports.init = (app, options, cB)->
  # enable authentication
  app.enableAuth()
  if (options and typeof options is 'function')
    cB = arguments[1]
    options = {}
  authOptions = if options?.hasOwnProperty 'authOptions' then options.authOptions else {}
  app.models.User.restore = (token, cB) ->
    app.models.AccessToken.findOne { where: id: token }, (e, token) ->
      # console.log arguments
      cB.apply this, arguments
  app.models.User.remoteMethod 'restore',
    accepts: [ {
      arg: 'token'
      type: 'string'
      required: true
    } ]
    http:
      path: '/login/restore/:token'
      verb: 'get'
    returns:
      type: 'Object'
      root: true

  app.models.User.logout = (req, res, cB) ->
    return cB 'accessToken not defined' unless hasAccessToken req
    app.models.AccessToken.destroyById req.accessToken.id, ->
      delete req.session.userId
      delete req.signedCookies.authorization
      cB status: 204 
  app.models.User.remoteMethod 'logout',
    accepts: [
      {
        arg: 'req'
        type: 'object'
        'http': source: 'req'
      }
      {
        arg: 'res'
        type: 'object'
        'http': source: 'res'
      }
    ]
    http:
      path: '/login'
      verb: 'delete'
      status: 204
    returns:
      type: 'null'
      root: true
  app.post '/reset-password', (req, res, next) ->
    return res.sendStatus 401 unless hasAccessToken req
    #verify passwords match
    unless (req.body.password? and req.body.confirmation?) and (req.body.password.match new RegExp "^#{req.body.confirmation}+$")?
      return res.sendStatus 400, new Error 'Passwords do not match'
    app.models.User.findById req.accessToken.userId, (e, user) ->
      return res.sendStatus 404 if e?
      user.updateAttribute 'password', req.body.password, (e, user) ->
        return res.sendStatus 404 if e?
        res.json
          title: 'Password reset success'
          content: 'Your password has been reset successfully'
          redirectTo: '/'
          redirectToLinkText: 'Log in'
  app.use loopback.token model: app.models.accessToken
  app.use (req, res, next) ->
    unless hasAccessToken(req) and req.signedCookies
      res.clearCookie 'authorization'
      next()
    else
      app.models.User.findById req.accessToken.userId, (e, user) ->
        console.log e if e?
        req.session.userId = req.accessToken.userId
        req.user = user
        console.log "set user attrs upon request"
        console.log user
        next()
  handleAuth = (context, result, next) ->
    unless result?.id?
      context.res.cookie 'authorization', result.id,
        httpOnly: true
        signed: true
      app.models.User.findById result.userId, authOptions, (e, user) ->
        context.req.session.regenerate (err)=>
          context.req.session.userId = result.userId
          context.req.user = user
          next()
    else
      next()
  app.models.User.afterRemote 'login', handleAuth
  app.models.User.afterRemote 'restore', handleAuth
  app.models.User.afterRemote 'logout', (context, result, next) ->
    delete context.req.user if context.req.hasOwnProperty 'user'
    context.res.clearCookie 'authorization'
  cB()