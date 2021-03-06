// Responsible for creating a server
// Responsible for connecting my server to my postgres database


// const User = require("./models/user.js");

// Server stuff
const express = require('express');

const app = express();

// Database stuff
const Sequelize = require('sequelize');

app.use(express.static(__dirname + '/'));

// Creating the connection
const db = new Sequelize('d9fdiar6qckcfb', 'gvrvcxzsgpiwqs', '2cfcba54760268d5e8aa1898654876297ddfe9701f8d6c258924f7d6a4e32038', {
  dialect: 'postgres',
  host: "ec2-184-72-238-22.compute-1.amazonaws.com",
  port: 5432,
  password: "2cfcba54760268d5e8aa1898654876297ddfe9701f8d6c258924f7d6a4e32038",
  define:{
    timestamps:false
  }
});

db
  .authenticate()
  .then(() => {
    console.log('Connection has been established successfully.');
  })
  .catch((err) => {
    console.error('Unable to connect to the database:', err);
  });


// Define what a user looks like in the user table (schema)

const User = db.define('user', {
  username: {
    type: Sequelize.STRING
  },
  password: {
    type: Sequelize.STRING
  }
});


// Sync up User table that we just created with the database
User.sync()
  .then(() => {
  });


// Allow all incoming requests (regardless of origin)
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*'); // Accept all origins
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
  next();
});


// Be able to parse any incoming requests and successfully grab body information
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

//app.get('/', (request, response) => {
  //response.json('All of my passwrods from a database');
//});

app.get('/login', (request, response) => {
  console.log(__dirname)
  console.log()
  response.sendFile(__dirname+"/pages/Login.html");
});

app.get('/reg_page', (request, response) => {
  response.sendFile(__dirname+ "/pages/reg_page.html");
});

app.get('/home', (request, response) => {
  response.sendFile(__dirname+"/pages/home.html");
});

app.get('/encryption', (request, response) => {
  response.sendFile(__dirname+"/pages/Encryption.html");
});

app.post('/login', (request, response) => {
  console.log('What is my request body (the information my user is sending in: ', request.body);
  User.findOne({
    where: {
      username: request.body.username,
      password: request.body.password
    }
  })
    .then((user) => {
      if (!user) {
        response.json('Wrong username or password');
      } else {
        response.json(user);
      }
    });
});

app.post('/new', (request, response) => {
  console.log(request.body.username);
  User.create({
        username: request.body.username,
        password: request.body.password
      })
    .then((user) => {
      response.json(user);
    });
});


//allow other files to use the database
module.exports = db;

app.listen(process.env.PORT || 3000, () => {
  console.log('Succesfully listening on port 3000');
});
