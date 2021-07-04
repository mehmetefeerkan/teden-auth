var express = require('express');
var app = express();
const jsonServer = require('json-server')
const jServer = jsonServer.create()
const router = jsonServer.router('db.json')
const middlewares = jsonServer.defaults()
const axios = require('axios')
const crypto = require('crypto')
var md5 = require('md5');
const { uuid } = require('uuidv4');


app.use(express.json())
app.use(require('express-useragent').express())

let strictRoutes = ["/login", "/register", "/logout"]

app.use((req, res, next) => {
    let acAd = req.originalUrl
    if (strictRoutes.includes(acAd)) {
        if (req.body.username && req.body.password && req.body) {
            next()
        }
        else {
            res.send(406)
        }
    }
});

jServer.use(middlewares)
jServer.use(router)

jServer.listen(3000, () => {
    console.log('JSON Server is running')
})




app.post('/register', function (req, res) {
    let user = req.body
    let userID = generateUserID(user.username)
    let accessing = req.headers['x-forwarded-for'] || req.socket.remoteAddress

    axios.post('http://localhost:3000/userDB', {
        id: userID,
        username: user.username,
        password: user.password,
        loggedIn: false,
        requests: 0
    })
        .then(function (response) {
            if (response.status === 201) {
                res.send(200, { userID: userID })
                log.register.success(generateUserID(user.username), user.username, user.password, accessing, req.useragent)
            }
            else {
                res.send(403)
                log.register.failure(generateUserID(user.username), user.username, user.password, accessing, req.useragent)
            }
        })
        .catch(function (error) {
            res.send(406, "USER_ALREADY_EXISTS")
        });
})

app.post('/login', async function (req, res) {
    let user = req.body
    let accessing = req.headers['x-forwarded-for'] || req.socket.remoteAddress
    let canProceed = true
    const userData = await axios.get('http://localhost:3000/userDB/' + generateUserID(user.username)).catch(function (error) {
        res.send(403, "USER_DOES_NOT_EXIST")
        canProceed = false
    })
    axios.patch('http://localhost:3000/userDB/' + generateUserID(user.username), {
        loggedIn: true
    })
    if (canProceed) {
        if ((userData.data.password === user.password)) {
            res.send(200, { userID: generateUserID(user.username) })
            log.login.success(generateUserID(user.username), user.username, user.password, accessing, req.useragent)
        } else {
            res.send(403, { error: "INVALID_CREDIDENTIALS" })
            log.login.failure(generateUserID(user.username), user.username, user.password, accessing, req.useragent)
        }
    }
})

app.post('/logout', async function (req, res) {
    let user = req.body
    let accessing = req.headers['x-forwarded-for'] || req.socket.remoteAddress
    let canProceed = true
    const userData = await axios.get('http://localhost:3000/userDB/' + generateUserID(user.username)).catch(function (error) {
        res.send(403, "USER_DOES_NOT_EXIST")
        canProceed = false
    })
    axios.patch('http://localhost:3000/userDB/' + generateUserID(user.username), {
        loggedIn: false
    })
    if (canProceed) {
        if (userData.data.password === user.password) {
            res.send(200)
            log.logout.success(generateUserID(user.username), user.username, user.password, accessing, req.useragent)
        } else {
            res.send(403, { error: "INVALID_CREDIDENTIALS" })
            log.logout.failure(generateUserID(user.username), user.username, user.password, accessing, req.useragent)
        }
    }
})

app.post('/talkAuth', async function (req, res) {
    let userIdentifier = req.body.userid
    if (userIdentifier !== undefined) {
        let accessing = req.headers['x-forwarded-for'] || req.socket.remoteAddress
        let canProceed = true
        const userData = await axios.get('http://localhost:3000/userDB/' + userIdentifier).catch(function (error) {
            res.send(403, "USER_DOES_NOT_EXIST")
            canProceed = false
        })
        axios.patch('http://localhost:3000/userDB/' + userIdentifier, {
            requests: userData.requests + 1
        })
        if (canProceed) {
            if (userData.data.loggedIn) {
                res.send(200)
            }
            else {
                res.send(403, { error: "USER_NOT_LOGGED_IN" })
            }
        } else {
            res.send(403, { error: "INVALID_CREDIDENTIALS" })
        }
    }
    else {
        res.send(405)
    }
})



function generateUserID(usn) {
    return md5(usn)
}


app.listen(3322, "127.0.0.1", () => {
    console.log('Express Server is running')
})

const log = {
    login: {
        success: function (userid, username, password, accessingFrom, useragent) {
            axios.post('http://localhost:3000/logs', {
                id: uuid(),
                type: "login-success",
                userid: userid,
                username: username,
                password: password,
                accessingFrom: accessingFrom,
                userAgent: (`${useragent.browser} | ${useragent.os} | ${useragent.platform}`),
                time: Date.now()
            })
                .catch(function (error) {
                    console.log(error)
                });
        },
        failure: function (userid, username, password, accessingFrom, useragent) {
            axios.post('http://localhost:3000/logs', {
                id: uuid(),
                type: "login-failed",
                userid: userid,
                username: username,
                password: password,
                accessingFrom: accessingFrom,
                userAgent: (`${useragent.browser} | ${useragent.os} | ${useragent.platform}`),
                time: Date.now()
            })
                .catch(function (error) {
                    console.log(error)
                });
        },
    },
    register: {
        success: function (userid, username, password, accessingFrom, useragent) {
            axios.post('http://localhost:3000/logs', {
                id: uuid(),
                type: "register-success",
                userid: userid,
                username: username,
                password: password,
                accessingFrom: accessingFrom,
                userAgent: (`${useragent.browser} | ${useragent.os} | ${useragent.platform}`),
                time: Date.now()
            })
                .catch(function (error) {
                    console.log(error)
                });
        },
        failure: function (userid, username, password, accessingFrom, useragent) {
            axios.post('http://localhost:3000/logs', {
                id: uuid(),
                type: "register-failed",
                userid: userid,
                username: username,
                password: password,
                accessingFrom: accessingFrom,
                userAgent: (`${useragent.browser} | ${useragent.os} | ${useragent.platform}`),
                time: Date.now()
            })
                .catch(function (error) {
                    console.log(error)
                });
        }
    },
    logout: {
        success: function (userid, username, password, accessingFrom, useragent) {
            axios.post('http://localhost:3000/logs', {
                id: uuid(),
                type: "logout-success",
                userid: userid,
                username: username,
                password: password,
                accessingFrom: accessingFrom,
                userAgent: (`${useragent.browser} | ${useragent.os} | ${useragent.platform}`),
                time: Date.now()
            })
                .catch(function (error) {
                    console.log(error)
                });
        },
        failure: function (userid, username, password, accessingFrom, useragent) {
            axios.post('http://localhost:3000/logs', {
                id: uuid(),
                type: "logout-failed",
                userid: userid,
                username: username,
                password: password,
                accessingFrom: accessingFrom,
                userAgent: (`${useragent.browser} | ${useragent.os} | ${useragent.platform}`),
                time: Date.now()
            })
                .catch(function (error) {
                    console.log(error)
                });
        }
    }
}