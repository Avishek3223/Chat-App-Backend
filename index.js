const express = require("express");
require('dotenv').config();
const cookieParser = require('cookie-parser')
const mongoose = require('mongoose');
const User = require('./models/User');
const Message = require('./models/message');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bcrypt = require("bcryptjs")
const ws = require('ws')

const app = express();
app.use(cors({
    credentials: true,
    origin: 'https://main--chatter-box23.netlify.app/',
}));

app.use(express.json());
app.use(cookieParser())

const port = process.env.PORT;

mongoose.connect(process.env.MONGODB_URL)
    .then(() => console.log('MongoDB connected'))
    .catch(err => console.error('MongoDB connection error:', err));

const jwtSecret = process.env.JWT_SECRET;
const bcryptSalt = bcrypt.genSaltSync(10);

async function getUserDataFromRequest(req) {
    const token = req.cookies.token;
    if (token) {
        return new Promise((resolve, reject) => {
            jwt.verify(token, jwtSecret, {}, (err, userData) => {
                if (err) {
                    reject(err);
                } else {
                    console.log("User data:", userData);
                    resolve(userData);
                }
            });
        });
    } else {
        return Promise.reject(new Error('No token provided'));
    }
}

app.get('/profile', (req, res) => {
    const token = req.cookies.token;
    if (token) {
        jwt.verify(token, jwtSecret, {}, (err, userData) => {
            if (err) throw err;
            console.log("User data:", userData); // Log the userData
            res.json(userData);
        })
    } else {
        res.status(401).json('no token')
    }
}); 

app.get('/messages/:userId', async (req, res) => {
    try {
        const userData = await getUserDataFromRequest(req);
        const { userId } = req.params;
        const ourUserId = userData.userId;
        const messages = await Message.find({
            sender: { $in: [ourUserId, userId] },
            recipient: { $in: [ourUserId, userId] },
        }).sort({ createdAt: 1 });
        res.json(messages);
    } catch (error) {
        console.error('Error fetching messages:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.post('/login', async (req, res) => {
    const { userName, password } = req.body;
    const foundUser = await User.findOne({ userName })
    if (foundUser) {
        const passOk = bcrypt.compareSync(password, foundUser.password)
        if (passOk) {
            jwt.sign({ userId: foundUser._id, userName }, jwtSecret, {}, (err, token) => {
                if (err) {
                    console.error('Error creating JWT:', err);
                    return res.status(500).json({ error: 'Internal Server Error' });
                }
                // Set token in cookie and send response
                res.cookie('token', token, { sameSite: 'none', secure: true }).status(201).json({
                    id: foundUser._id,
                });
            });
        }
    }
});

app.post('/register', async (req, res) => {
    const { userName, password } = req.body;
    const hashedPassword = bcrypt.hashSync(password, bcryptSalt);
    try {
        const createdUser = await User.create({ userName, password: hashPassword });
        console.log("User created:", createdUser); // Log the created user
        jwt.sign({ userId: createdUser._id, userName }, jwtSecret, {}, (err, token) => {
            if (err) {
                console.error('Error creating JWT:', err);
                return res.status(500).json({ error: 'Internal Server Error' });
            }
            // Set token in cookie and send response
            res.cookie('token', token, { sameSite: 'none', secure: true }).status(201).json({
                id: createdUser._id,
            });
        });
    } catch (e) {
        console.error('Error registering user:', e);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.get('/people', async (req,res) => {
    const users = await User.find({}, {'_id':1,userName:1});
    res.json(users);
  });
  

const server = app.listen(port, () => {
    console.log(`Server started on port ${port}`);
});

app.post('/logout', (req, res) => {
    res.clearCookie('token'); 
    res.status(200).json({ message: 'Logged out successfully' });
});


//read the username and id from the cookie for this connection
const wss = new ws.WebSocketServer({ server });
wss.on('connection', (connection, req) => {
    const cookies = req.headers.cookie;
    if (cookies) {
        const tokenCookieString = cookies.split(';').find(str => str.startsWith('token='));
        console.log(tokenCookieString)
        if (tokenCookieString) {
            const token = tokenCookieString.split('=')[1]
            if (token) {
                jwt.verify(token, jwtSecret, {}, (err, userData) => {
                    if (err) throw err;
                    const { userId, userName } = userData;
                    connection.userId = userId;
                    connection.userName = userName;
                })
            }
        }
    }

    connection.on('message', async (message) => {
        const messageData = JSON.parse(message.toString());
        const { recipient, text } = messageData;
        if (recipient && text) {
            const messageDOC = await Message.create({
                sender: connection.userId,
                recipient,
                text
            });
            [...wss.clients]
                .filter(c => c.userId === recipient)
                .forEach(c => c.send(JSON.stringify({
                    text,
                    sender: connection.userId,
                    id: messageDOC._id,
                })));
        }
    });

    //notify about online people
    [...wss.clients].forEach(client => {
        client.send(JSON.stringify({
            online: [...wss.clients].map(c => ({ userId: c.userId, userName: c.userName }))
        }))
    })
    console.log([...wss.clients].map(c => c.userName))
})