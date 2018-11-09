const express = require('express');
const auth = require('http-auth');
const debug = require('debug')('auth:authentication');
const crypto = require('crypto');
const router = express.Router();

/** HTTP Basic */
router.get('/http-basic', function(req, res, next) {
  const authData = req.get('Authorization') || '';

  const expectToken = Buffer.from("admin:basic").toString('base64')

  debug('http-basic:expect token', expectToken);

  if (authData) {
    const token = authData.split(' ')[1];
    if (token === expectToken) {
      res.status(200);
      res.render('index', { title: 'HTTP Base Demo', content: 'Welcome, my lord' });

      return;
    }
  }

  res.status(401);
  res.set('WWW-Authenticate', 'Basic realm="Auth Demo"');
  res.render('index', { title: 'HTTP Base Demo', content: 'You need to login' });
});

/** HTTP Digest */
const realm = 'http-digest'
const digest = auth.digest({
  realm,
}, (username, callback) => {
  const password = 'digest';

  let hash = crypto.createHash('MD5');
  hash.update(`${username}:${realm}:${password}`);

  callback(hash.digest('hex'));
});

router.get('/http-digest', auth.connect(digest), function(req, res, next) {
  res.status(200);
  res.render('index', { title: 'HTTP Digest Demo', content: 'Welcome, my lord' });
});

/* Form-Based */
router.get('/form-based', function(req, res, next) {
  if (req.session.views) {
    req.session.views += 1;
  } else {
    req.session.views = 1;
  }

  res.send('<p>you have viewed ' + req.session.views + ' times</p> <p>your session:</p><pre>' + JSON.stringify(req.session, '\n', 4) + '</pre>');
});

module.exports = router;
