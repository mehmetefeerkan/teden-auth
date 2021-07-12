console.log("Initializing")
var express = require('express');
console.log("Express loaded")
var app = express();
console.log("Express primed")
const jsonServer = require('json-server')
console.log("json-server loaded")
const jServer = jsonServer.create()
console.log("json-server created")
const router = jsonServer.router(dirname__ + '/db.json')
console.log("json-server database set")
const middlewares = jsonServer.defaults()
console.log("json-server middlewares set")
const axios = require('axios')
console.log("axios loaded")
const crypto = require('crypto')
console.log("crypto loaded")
var md5 = require('md5');
console.log("md5 loaded")
const { uuid } = require('uuidv4');
console.log("uuidv4 loaded")
const fs = require('fs')
console.log("uuidv4 loaded")
const cors = require('cors')
console.log("cors loaded")
const envar = require(__dirname + "/env.json")
console.log("Environment Variables loaded")


app.use(express.json())
console.log("Express middlewares loaded 3/1")
app.use(require('express-useragent').express())
console.log("Express middlewares loaded 3/2")
app.use(cors())
console.log("Express middlewares loaded 3/3")

let strictRoutes = ["/login", "/register", "/logout"]

app.use((req, res, next) => {
    let acAd = req.originalUrl
    if (strictRoutes.includes(acAd)) {
        if (req.body.username && req.body.password && req.body) {
            next()
        }
        else {
            res.send(200, { error: "INVALID_REQUEST" })
        }
    }
    else {
        next()
    }
});

jServer.use(middlewares)
jServer.use(router)
const dbIp = envar.databaseIp
const dbPort = envar.databasePort
jServer.listen(dbPort, dbIp, () => {
    console.log('JSON Server is running on ' + dbIp + ':' + dbPort)
})




app.post('/register', function (req, res) {
    let user = req.body
    let userID = generateUserID(user.username)
    let accessing = req.headers['x-forwarded-for'] || req.socket.remoteAddress

    axios.post(`http://${dbIp}:${dbPort}/userDB/`, {
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
                res.send(200, { error: "INVALID_CREDIDENTIALS" })
                log.register.failure(generateUserID(user.username), user.username, user.password, accessing, req.useragent)
            }
        })
        .catch(function (error) {
            res.send(200, "USER_ALREADY_EXISTS")
        });
})

app.post('/login', async function (req, res) {
    let user = req.body
    let accessing = req.headers['x-forwarded-for'] || req.socket.remoteAddress
    let canProceed = true
    const userData = await axios.get(`http://${dbIp}:${dbPort}/userDB/` + generateUserID(user.username)).catch(function (error) {
        res.send(200, { userID: "INVALID_CREDIDENTIALS" })
        canProceed = false
    })
    axios.patch(`http://${dbIp}:${dbPort}/userDB/` + generateUserID(user.username), {
        loggedIn: true
    })
    if (canProceed) {
        if ((userData.data.password === user.password)) {
            res.send(200, { userID: generateUserID(user.username) })
            log.login.success(generateUserID(user.username), user.username, user.password, accessing, req.useragent)
        } else {
            res.send(200, { error: "INVALID_CREDIDENTIALS" })
            log.login.failure(generateUserID(user.username), user.username, user.password, accessing, req.useragent)
        }
    }
})

app.get('/logout/:userid', async function (req, res) {
    let userIdentifier = req.params.userid
    if (userIdentifier !== undefined) {
        let accessing = req.headers['x-forwarded-for'] || req.socket.remoteAddress
        let canProceed = true
        const userData = await axios.get(`http://${dbIp}:${dbPort}/userDB/` + userIdentifier).catch(function (error) {
            res.send(200, "USER_DOES_NOT_EXIST")
            canProceed = false
        })
        if (canProceed) {
            if (userData.data.loggedIn) {
                axios.patch(`http://${dbIp}:${dbPort}/userDB/` + userIdentifier, {
                    loggedIn: false
                })
                res.send(200)
            }
            else {
                res.send(200, { error: "USER_NOT_LOGGED_IN" })
            }
        }
    }
    else {
        res.send(200, {error: "INVALID_REQUEST"})
    }
})

app.post('/talkAuth', async function (req, res) {
    let userIdentifier = req.body.userid
    if (userIdentifier !== undefined) {
        let accessing = req.headers['x-forwarded-for'] || req.socket.remoteAddress
        let canProceed = true
        const userData = await axios.get(`http://${dbIp}:${dbPort}/userDB/` + userIdentifier).catch(function (error) {
            res.send(403, "USER_DOES_NOT_EXIST")
            canProceed = false
        })
        axios.patch(`http://${dbIp}:${dbPort}/userDB/` + userIdentifier, {
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

app.get('/logs', async function (req, res) {
    let canProceed = true
    const logData = await axios.get(`http://${dbIp}:${dbPort}/logs`).catch(function (error) {
        res.send(200, { userID: "UNKNOWN_DATABASE_ERROR" })
        canProceed = false
    })
    if (canProceed){
        res.send(logData)
    }
})

function generateUserID(usn) {
    return md5(usn)
}

/*
app.listen(3322, "127.0.0.1", () => {
    console.log('Express Server is running')
}) */

const log = {
    login: {
        success: function (userid, username, password, accessingFrom, useragent) {
            axios.post(`http://${dbIp}:${dbPort}/logs`, {
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
            axios.post(`http://${dbIp}:${dbPort}/logs`, {
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
            axios.post(`http://${dbIp}:${dbPort}/logs`, {
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
            axios.post(`http://${dbIp}:${dbPort}/logs`, {
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
            axios.post(`http://${dbIp}:${dbPort}/logs`, {
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
            axios.post(`http://${dbIp}:${dbPort}/logs`, {
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



const https = require('https');
console.log("https loaded")
const http = require('http');
console.log("http loaded")

const httpServer = http.createServer(app);
console.log("httpServer created")


const httpsServer = https.createServer({
    key: (envar.privKey),
    cert:(envar.fullChain),
}, app);

console.log("certificated loaded")


httpServer.listen(80, (envar.hostIp), () => {
    console.log('HTTP Server running on port 80');
});

httpsServer.listen(443, (envar.hostIp), () => {
    console.log('HTTPS Server running on port 443');
});
