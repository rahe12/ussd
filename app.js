const express = require('express');
const bodyParser = require('body-parser');

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));

app.post('/ussd', (req, res) => {
    // Read the variables sent via POST from the API
    const {
        sessionId,
        serviceCode,
        phoneNumber,
        text,
    } = req.body;

    let response = '';

    if (text === '') {
        // First request from the user
        response = `CON What would you like to check
1. My account
2. My phone number`;
    } else if (text === '1') {
        response = `CON Choose account information you want to view
1. Account number`;
    } else if (text === '2') {
        response = `END Your phone number is ${phoneNumber}`;
    } else if (text === '1*1') {
        const accountNumber = 'ACC100101';
        response = `END Your account number is ${accountNumber}`;
    } else {
        response = 'END Invalid input';
    }

    // Set response headers and send response
    res.set('Content-Type', 'text/plain');
    res.send(response);
});

// Start server on port 3000
app.listen(3000, () => {
    console.log('USSD app listening on port 3000');
});
