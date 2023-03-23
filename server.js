const express = require("express")
const app = express()
const jwt = require('jsonwebtoken')
const addUsers = require("./database").addUser
require('dotenv').config()
const bcrypt = require('bcrypt');

app.set('view-engine', 'ejs')
app.use(express.urlencoded({extended: false}))
app.use(express.json())

var currentKey =""
var currentPassword =""

app.get('/', (req,res) => {
    res.redirect("/identify")
})

app.get('/identify', (req, res) => {
    res.render('identify.ejs')
})

app.post('/identify', (req, res) => {
    const username = req.body.password
    const token = jwt.sign(username, process.env.ACCESS_TOKEN_SECRET)
    currentKey = token
    currentPassword = username
    res.redirect("/granted")
})

function authenticateToken(req, res, next) {
    if(currentKey == "") {
        res.redirect("/identify")
    } else if (jwt.verify(currentKey, process.env.ACCESS_TOKEN_SECRET)) {
        next()
    } else {
        res.redirect("/identify")
    }
}

app.get('/granted', authenticateToken, (req, res) => {
    res.render("start.ejs")
})

async function createUsers(username, name, role, password) {
    let encryptedPassowrd = await bcrypt.hash(password, 10);
    await addUsers(username, name, role, encryptedPassowrd)
}

//Create default users

createUsers('id1','user1', 'STUDENT1', 'password');
createUsers('id2','user2', 'STUDENT2', 'password2');
createUsers('id3', 'user3', 'TEACHER', 'password3');
createUsers('admin', 'admin', 'ADMIN', 'admin');



app.listen(8000, () => {
console.log("Server is up on port 8000")
})