path     = require 'path'
loopback = require "#{path.join process.cwd(), 'node_modules', 'loopback'}"

module.exports.init = (app, cB)->
  # enable authentication
  app.enableAuth()

  app.models.User.restore = (token, cB) ->
    app.models.AccessToken.findOne { where: id: token }, (e, token) ->
      console.log arguments
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
    return cB 'accessToken not defined' unless req.hasOwnProperty 'accessToken' and req.accessToken?
    app.models.AccessToken.destroyById req.accessToken.id, ->
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
    return res.sendStatus 401 unless req.accessToken
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
    res.clearCookie 'authorization' unless req.accessToken? and req.signedCookies
    next()

  handleAuth = (context, result, next) ->
    if result != null and result.id != null
      context.res.cookie 'authorization', result.id,
        httpOnly: true
        signed: true
    next()

  app.models.User.afterRemote 'login', handleAuth
  app.models.User.afterRemote 'restore', handleAuth
  app.models.User.afterRemote 'logout', (context, result, next) ->
    context.res.clearCookie 'authorization'
    
  cB()