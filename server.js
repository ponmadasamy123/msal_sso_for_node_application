const express = require('express')
const { isUserAuthenticated } = require('./auth/useauth')
const authRoute = require("./authRoute")
const app = express()
app.use(authRoute)


app.get("*",
    isUserAuthenticated,
    (req, res, next) => {
        console.log("user Authenticated");
        next()
    })


app.get("/", (req, res) => {
    res.send("Hello world")
})



app.listen(3001, console.log("App is running in port 3001"))