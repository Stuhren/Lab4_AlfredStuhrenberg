const express = require("express")
const app = express()
const jwt = require('jsonwebtoken')
const db = require("./database")
require('dotenv').config()
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');


app.set('view-engine', 'ejs')
app.use(express.urlencoded({extended: false}))
app.use(express.json())
app.use(cookieParser())

//Deletes current and creates a new database everytime server is run to not overflow with information.
db.createDb()


var currentKey =""


app.get('/', (req,res) => {
    res.redirect("/identify")
})

app.get('/identify', (req, res) => {
    res.render('identify.ejs')
})

app.post('/identify', async (req, res) => {
    try {
        if(req.body.userId && req.body.password) {
            var dbUser = await db.getUser(req.body.userId)
            if (!dbUser) {
                throw new Error('User not found')
            }
            var userPassword = await db.getPasswordForUser(req.body.userId)
            var passwordMatch = await bcrypt.compare(req.body.password, userPassword)
            if (passwordMatch) {
                let userObj = { username: req.body.userId, role: dbUser.role };
                const token = jwt.sign(userObj, process.env.ACCESS_TOKEN_SECRET)
                currentKey = token
                res.cookie("jwt", token, { httpOnly: true }).status(200).redirect(`/users/${dbUser.username}`);
            } else {
                throw new Error('Incorrect password')
            }
        } else {
            throw new Error('Missing username or password')
        }
    } catch (error) {
        console.error(error)
        res.status(400).render('error.ejs', { error })
    }
})


app.get('/granted', authenticateToken, (req, res) => {
    res.render("start.ejs")
})

app.get('/admin', authenticateToken, authorizeRole(["ADMIN"]), async (req, res) => {
    try {
        users = await db.getUsers()
        res.render("admin.ejs", users)
    } catch (error) {
        console.error(error)
        res.status(500).render('fail.ejs', { error })
    }
})

app.get('/student1', authenticateToken, authorizeRole(["STUDENT1","ADMIN","TEACHER"]), async (req, res) => {
    try {
        const user = await getUserFromToken(req);
        res.render('student1.ejs', { user: user })
    } catch (error) {
        console.error(error)
        res.status(500).render('fail.ejs', {error})
    }
})

app.get('/student2', authenticateToken, authorizeRole(["STUDENT2","ADMIN","TEACHER"]), async (req, res) => {
    try {
        const user = await getUserFromToken(req);
        res.render('student2.ejs', { user: user })
    } catch (error) {
        console.error(error)
        res.status(500).render('fail.ejs', {error})
    }
})

app.get('/teacher', authenticateToken, authorizeRole(["TEACHER","ADMIN"]), async (req, res) => {
    try {
        res.render('teacher.ejs')
    } catch (error) {
        console.error(error)
        res.status(500).render('fail.ejs', {error})
    }
})

app.get('/register', (req, res) => {
    res.render('register.ejs')
})

app.post('/register', async (req, res) => {
//If username or password is empty, it will fail
if (req.body.password === '' || req.body.username === '') {
    res.status(400).render('fail.ejs', { message: "Please enter a username AND password" });
    return;
  }

  //If filled up, inserted into db.
  try {
    createUsers(req.body.userId, req.body.name, req.body.role, req.body.password)
    res.status(200).redirect('/identify')
  } catch (error) {
    res.status(400).render('fail.ejs', { message: error })
    return;
  }
})

//Only the user with the exact userId is allowed to enter, not even people with the same roles are allowed.
app.get('/users/:userId', authenticateToken, async (req, res) => {
    try {
      const user = await getUserFromToken(req);
      if (req.params.userId === user.username) {
        res.render('users.ejs', { user: user });
      } else {
        throw new Error('You are not authorized to view this user');
      }
    } catch (error) {
      console.error(error)
      res.status(500).redirect('/identify');
    }
  })


function authenticateToken(req, res, next) {
    try {
      if(currentKey === "") {
        res.redirect("/identify")
      } else if (jwt.verify(currentKey, process.env.ACCESS_TOKEN_SECRET)) {
        next()
      } else {
        res.status(401).redirect("/identify")
      }
    } catch (error) {
      res.status(500).send({ error: "Authentication failed" });
    }
  }
  
  
  function authorizeRole(requiredRoles) {
    return async (req, res, next) => {
      try {
        const user = await getUserFromToken(req);
        if (requiredRoles.includes(user.role)) {
          next();
        } else {
          res.redirect('/identify');
        }
      } catch (error) {
        console.log(error);
        res.status(500).send({ error: "Authorization failed" });
      }
    }
  }
  
  async function getUserFromToken(req) {
    try {
      const token = req.cookies.jwt;
      const decryptedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
      const user = await db.getUser(decryptedToken.username);
      return user;
    } catch (error) {
      console.log(error);
      throw new Error("Failed to get user from token");
    }
  }
  
  
  async function createUsers(username, name, role, password) {
    try {
      let encryptedPassword = await bcrypt.hash(password, 10);
      await db.addUser(username, name, role, encryptedPassword)
    } catch (error) {
      console.log(error);
      throw new Error("Failed to create user");
    }
  }
  
  //Create default users
  (async () => {
    try {
      await createUsers('id1','user1', 'STUDENT1', 'password');
      await createUsers('id2','user2', 'STUDENT2', 'password2');
      await createUsers('id3', 'user3', 'TEACHER', 'password3');
      await createUsers('admin', 'admin', 'ADMIN', 'admin');
    } catch (error) {
      console.log(error);
    }
  })();
  
  app.listen(process.env.PORT, () => {
    console.log("Server is up on port 8000");
  });