const crypto = require("crypto");
const Sequelize = require("sequelize");
//set up a path to the exported database
const db = require("../index.js");

// Define what a user looks like in the user table (schema)

const User = db.define('user', {
  username: {
    type: Sequelize.STRING,
    allowNull: false,
    unique: true
  },
  password: {
    type: Sequelize.STRING,
    get(){
    	return ()=> this.getDataValue("password");
    }
  },
   	salt: {
    type: Sequelize.STRING,
    get(){
    	return ()=> this.getDataValue("salt");
    }
  }
});

User.generateSalt = function(){
	return crypto.randomBytes(16).toString("base64");
}

User.encryptPassword = function(plaintext, salt){
	return crypto.createHash("RSA-SHA256").update(plaintext).update(salt).digest("hex");
}

const setSaltAndPassword = user =>{
	if(user.changed("password")){
		user.salt = User.generateSalt();
		user.password = User.encryptPassword(user.password(), user.salt());
	}
}

User.beforeCreate(setSaltAndPassword);
User.beforeUpdate(setSaltAndPassword);
module.exports = User;

User.prototype.correctPassword = function(plaintext) {
  return User.encryptPassword(plaintext, this.salt()) === this.password();
}