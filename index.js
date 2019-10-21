const express = require('express');
const bcrypt = require('bcryptjs');
const sessions = require('express-session');
const KnexSessionsStore = require('connect-session-knex')(sessions);

// const authRouter = require('../auth/auth-router.js');
// const usersRouter = require('../users/users-router.js');
const knexConfig = require('./data/db-config.js');

const db = require('./data/db-config.js');
const Users = require('./users/users-model.js');

const server = express();

const sessionConfiguration = {
  name: "TYLER", //Default would be 'sid'
  secret: 'keep it secret, keep it safe!', //Use an environment variable for this
  cookie: {
    httpOnly: true, //JS cannot access the cookie
    maxAge: 1000 * 60 * 60, //Expiration time in milliseconds
    secure: false,
  },
  resave: false,
  saveUninitialized: true,

  store: new KnexSessionsStore({
    knex: knexConfig,
    createtable: true,
    clearInterval: 1000 * 60 * 30, //Delete *expired* sessions every 30 min
  })

}

server.use(sessions(sessionConfiguration));
server.use(express.json());

server.get('/', (req, res) => {
  res.send("It's alive!");
});

server.post('/api/register', (req, res) => {
  let user = req.body;

  // validate the user

  // hash the password
  const hash = bcrypt.hashSync(user.password, 8);

  // we override the password with the hash
  user.password = hash;

  Users.add(user)
    .then(saved => {
      res.status(201).json(saved);
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

server.post('/api/login', (req, res) => {
  let { username, password } = req.body;

  console.log('Pre Login', req.session);

  if (username && password) {
    Users.findBy({ username })
      .first()
      .then(user => {
        if (user && bcrypt.compareSync(password, user.password)) {

          req.session.username = user.username;

          console.log('Login', req.session);

          res.status(200).json({ message: `Welcome ${user.username}!` });
        } else {
          res.status(401).json({ message: 'You cannot pass!!' });
        }
      })
      .catch(error => {
        res.status(500).json(error);
      });
  } else {
    res.status(400).json({ message: 'please provide credentials' });
  }
});

server.get('/api/users', protected, (req, res) => {
  console.log('username', req.session.username);


  Users.find()
    .then(users => {
      res.json(users);
    })
    .catch(err => res.send(err));
});

server.get('/hash', (req, res) => {
  const password = req.headers.authorization;

  if (password) {
    const hash = bcrypt.hashSync(password, 10);

    res.status(200).json({ hash });
  } else {
    res.status(400).json({ message: 'please provide credentials' });
  }
});

server.get('/api/logout', (req, res) => {
  console.log('Session', req.session);

  if (req.session) {
    req.session.destroy(err => {
      res
        .status(200)
        .json({ Message: 'Session Destroyed; user logged out' })
    });
  } else {
    res.status(200).json({ Message: 'Already logged out' })
  }

})


function protected(req, res, next) {
  // const { username, password } = req.headers;

  if (req.session && req.session.username) {

    next();
  } else {
    res.status(401).json({ message: 'You cannot pass' });
  }
}

const port = process.env.PORT || 7777;
server.listen(port, () => console.log(`\n** Running on port ${port} **\n`));
