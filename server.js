const express = require("express")
const app = express()
const jwt = require('jsonwebtoken')
const db = require("./database")
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

app.post('/identify', async (req, res) => {
    if(req.body.userId && req.body.password) {
        var userPassword = await db.getPasswordForUser(req.body.userId)
        var passwordMatch = await bcrypt.compare(req.body.password, userPassword)
        if (passwordMatch) {
            const username = req.body.password
            const token = jwt.sign(username, process.env.ACCESS_TOKEN_SECRET)
            currentKey = token
            currentPassword = username
            res.redirect("/granted")
        } else {
            res.redirect('identify.ejs')
        }
    } else {
        res.redirect('identify.ejs')
    }
    
})


app.get('/granted', authenticateToken, (req, res) => {
    res.render("start.ejs")
})

app.get('/admin', async (req, res) => {
    users = await db.getUsers()
    res.render("admin.ejs", users)
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

async function createUsers(username, name, role, password) {
    let encryptedPassowrd = await bcrypt.hash(password, 10);
    await db.addUser(username, name, role, encryptedPassowrd)
}



//Create default users
createUsers('id1','user1', 'STUDENT1', 'password');
createUsers('id2','user2', 'STUDENT2', 'password2');
createUsers('id3', 'user3', 'TEACHER', 'password3');
createUsers('admin', 'admin', 'ADMIN', 'admin');



app.listen(8000, () => {
console.log("Server is up on port 8000")
})