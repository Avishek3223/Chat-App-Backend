const express = require("express");
require('dotenv').config();
const cookieParser = require('cookie-parser');
const mongoose = require('mongoose');
const User = require('./models/User');
const Message = require('./models/Message');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bcrypt = require("bcryptjs");
const ws = require('ws');
const { isValidObjectId } = mongoose;

const app = express();
app.use(cors({
    credentials: true,
    origin: true,
}));

app.use(express.json());
app.use(cookieParser());

const port = process.env.PORT || 5000;

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

app.get('/profile', async (req, res) => {
    try {
        const userData = await getUserDataFromRequest(req);
        res.json(userData);
    } catch (error) {
        res.status(401).json({ error: 'Unauthorized' });
    }
});

app.get('/messages/:userId', async (req, res) => {
    try {
        const userData = await getUserDataFromRequest(req);
        const { userId } = req.params;
        const ourUserId = userData.userId;
        
        if (!isValidObjectId(userId)) {
            return res.status(400).json({ error: 'Invalid user ID' });
        }

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
    try {
        const foundUser = await User.findOne({ userName });
        if (foundUser) {
            const passOk = bcrypt.compareSync(password, foundUser.password);
            if (passOk) {
                jwt.sign({ userId: foundUser._id, userName }, jwtSecret, {}, (err, token) => {
                    if (err) {
                        console.error('Error creating JWT:', err);
                        return res.status(500).json({ error: 'Internal Server Error' });
                    }
                    res.cookie('token', token, { sameSite: 'none', secure: true }).status(201).json({
                        id: foundUser._id,
                    });
                });
            } else {
                res.status(401).json({ error: 'Invalid credentials' });
            }
        } else {
            res.status(401).json({ error: 'User not found' });
        }
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.post('/register', async (req, res) => {
    const { userName, password } = req.body;
    const hashedPassword = bcrypt.hashSync(password, bcryptSalt);  // Correctly hashing password
    try {
        const createdUser = await User.create({ userName, password: hashedPassword });
        console.log("User created:", createdUser);
        jwt.sign({ userId: createdUser._id, userName }, jwtSecret, {}, (err, token) => {
            if (err) {
                console.error('Error creating JWT:', err);
                return res.status(500).json({ error: 'Internal Server Error' });
            }
            res.cookie('token', token, { sameSite: 'none', secure: true }).status(201).json({
                id: createdUser._id,
            });
        });
    } catch (error) {
        console.error('Error registering user:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.get('/people', async (req, res) => {
    try {
        const users = await User.find({}, { '_id': 1, userName: 1 });
        res.json(users);
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.post('/logout', (req, res) => {
    res.cookie('token', '', { sameSite: 'none', secure: true }).json('ok');
});

const server = app.listen(port, () => {
    console.log(`Server started on port ${port}`);
});

// WebSocket setup
const wss = new ws.WebSocketServer({ server });
wss.on('connection', (connection, req) => {
    const cookies = req.headers.cookie;
    if (cookies) {
        const tokenCookieString = cookies.split(';').find(str => str.trim().startsWith('token='));
        if (tokenCookieString) {
            const token = tokenCookieString.split('=')[1];
            if (token) {
                jwt.verify(token, jwtSecret, {}, (err, userData) => {
                    if (err) throw err;
                    const { userId, userName } = userData;
                    connection.userId = userId;
                    connection.userName = userName;
                });
            }
        }
    }

    connection.on('message', async (message) => {
        const messageData = JSON.parse(message.toString());
        const { recipient, text } = messageData;
        
        if (!isValidObjectId(recipient)) {
            return connection.send(JSON.stringify({ error: 'Invalid recipient ID' }));
        }

        if (recipient && text) {
            try {
                const messageDoc = await Message.create({
                    sender: connection.userId,
                    recipient,
                    text,
                });
                [...wss.clients]
                    .filter(c => c.userId === recipient)
                    .forEach(c => c.send(JSON.stringify({
                        text,
                        sender: connection.userId,
                        id: messageDoc._id,
                    })));
            } catch (error) {
                console.error('Error creating message:', error);
            }
        }
    });

    // Notify about online people
    [...wss.clients].forEach(client => {
        client.send(JSON.stringify({
            online: [...wss.clients].map(c => ({ userId: c.userId, userName: c.userName })),
        }));
    });
});
