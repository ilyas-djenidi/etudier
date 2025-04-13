const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');

const app = express();
const port = 3000;

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname)));

// Valid accounts
const validAccounts = [
    { username: "admin", password: "popo" },
    { username: "user", password: "kaka" }
];

// Store failed attempts
const failedAttempts = new Map();
const blockedIPs = new Map();

// Middleware to check if IP is blocked
const checkIPBlock = (req, res, next) => {
    const clientIP = req.ip;
    if (blockedIPs.has(clientIP)) {
        const blockEndTime = blockedIPs.get(clientIP);
        if (Date.now() < blockEndTime) {
            return res.redirect('/login?error=Your IP is blocked for 30 seconds due to multiple failed attempts');
        } else {
            blockedIPs.delete(clientIP);
            failedAttempts.delete(clientIP);
        }
    }
    next();
};

// Routes
app.get('/', (req, res) => {
    res.redirect('/login');
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'login.html'));
});

app.post('/login', checkIPBlock, (req, res) => {
    const { username, password } = req.body;
    const clientIP = req.ip;

    // Check if username exists
    const userAccount = validAccounts.find(account => account.username === username);

    if (!userAccount) {
        // Track failed attempts
        const attempts = (failedAttempts.get(clientIP) || 0) + 1;
        failedAttempts.set(clientIP, attempts);

        // Check if attempts exceed limit
        if (attempts > 3) {
            blockedIPs.set(clientIP, Date.now() + 30000); // Block for 30 seconds
            return res.redirect('/login?error=Your IP is blocked for 30 seconds due to multiple failed attempts');
        }

        return res.redirect('/login?error=Invalid username');
    }

    // Check password
    if (userAccount.password !== password) {
        // Track failed attempts
        const attempts = (failedAttempts.get(clientIP) || 0) + 1;
        failedAttempts.set(clientIP, attempts);

        // Check if attempts exceed limit
        if (attempts > 3) {
            blockedIPs.set(clientIP, Date.now() + 30000); // Block for 30 seconds
            return res.redirect('/login?error=Your IP is blocked for 30 seconds due to multiple failed attempts');
        }

        return res.redirect('/login?error=Incorrect password');
    }

    // Successful login
    failedAttempts.delete(clientIP);
    res.send('Login successful!');
});

const startServer = (initialPort) => {
    const server = app.listen(initialPort)
        .on('error', (err) => {
            if (err.code === 'EADDRINUSE') {
                console.log(`Port ${initialPort} is busy, trying ${initialPort + 1}...`);
                server.close();
                startServer(initialPort + 1);
            } else {
                console.error('Server error:', err);
            }
        })
        .on('listening', () => {
            const actualPort = server.address().port;
            console.log(`Server running at http://localhost:${actualPort}`);
        });
};

// Replace the existing app.listen with this call
startServer(port);