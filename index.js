const express = require("express")
const speakeasy = require("speakeasy")
const uuid = require("uuid")
const { JsonDB } = require("node-json-db")
const { Config } = require("node-json-db/dist/lib/JsonDBConfig")

const app = express()
app.use(express.json())

const db = new JsonDB(new Config("myDatabase", true, false, "/"))

app.get("/api", (request, response) => response.json({ message: "Welcome To Benion Two Factor Authentication" }))

// Register A User & Create A Temp Secret
app.post("/api/register", (request, response) => {
    const id = uuid.v4()

    try {
        const path = `/user/${ id }`
        const temp_secret = speakeasy.generateSecret()
        db.push(path, { id, temp_secret })
        response.json({ id, secret: temp_secret.base32 })
    } catch (error) {
        console.log(error)
        response.status(500).json({ message: "Error Generating Secret" })
    }
})

// Verify Token & Make The Token Permanent
app.post("/api/verify", (request, response) => {
    const { token, userId } = request.body

    try {
        const path = `/user/${ userId }`
        const user = db.getData(path)
        const { base32: secret } = user.temp_secret
        const verified = speakeasy.totp.verify({ secret, encoding: "base32", token })

        if (verified) {
            db.push(path, { id: userId, secret: user.temp_secret})
            response.json({ verified: true })
        } else {
            response.json({ verified: false })
        }
    } catch (error) {
        console.log(error)
        response.status(500).json({ message: "Error Finding User" })
    }
})

// Validate Token
app.post("/api/validate", (request, response) => {
    const { token, userId } = request.body

    try {
        const path = `/user/${ userId }`
        const user = db.getData(path)
        const { base32: secret } = user.secret
        const tokenValidates = speakeasy.totp.verify({ secret, encoding: "base32", token, window: 1 })

        if (tokenValidates) {
            response.json({ validated: true })
        } else {
            response.json({ validated: false })
        }
    } catch (error) {
        console.log(error)
        response.status(500).json({ message: "Error Finding User" })
    }
})

const PORT = process.env.PORT || 8828
app.listen(PORT, () => console.log(`Benion 2FA Auth Server Started At Port ${ PORT }`))