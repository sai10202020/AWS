// backend.js
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');




const multer = require('multer');
const { v4: uuidv4 } = require('uuid');

// --- AWS SDK Imports and Configuration ---
const AWS = require('aws-sdk');

// IMPORTANT: For AWS deployment, it's best practice to use IAM Roles
// and NOT hardcode credentials. However, as requested, they are included here.
// For production, remove these lines and assign an IAM Role to your EC2 instance.
AWS.config.update({
    region: 'ap-south-1', // IMPORTANT: This region must match where your DynamoDB tables are located.
    accessKeyId: 'AKIAVEP3EDM5K3LA5J47',
    secretAccessKey: 'YfIszgolrWKUglxC6Q85HSb3V0qhDsa00yv6jcIP'
});

// Create a DynamoDB DocumentClient.
const dynamodb = new AWS.DynamoDB.DocumentClient();
// --- END AWS SDK Setup ---

const SECRET_KEY = 'jwt_secret_key_54742384238423_ahfgrdtTFHHYJNMP[]yigfgfjdfjd=-+&+pqiel;,,dkvntegdv/cv,mbkzmbzbhsbha#&$^&(#_enD';
const PORT = 5000;
const app = express();

// Configure CORS for your deployed frontend.
app.use(cors({
    origin: [
        'http://localhost:3000',
        'http://localhost:5000',
        // Add your actual deployed frontend URL(s) here:
        // 'https://your-frontend-app-domain.com',
        // 'http://your-s3-website-bucket-name.s3-website-ap-south-1.amazonaws.com'
    ]
}));

app.use(bodyParser.json());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use('/static', express.static(path.join(__dirname, 'static')));

// Multer setup for file uploads (store image in memory as a Buffer)
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

// --- JWT Authentication Middleware ---
function authenticateUser(req, res, next) {
    // console.log('SERVER: authenticateUser middleware called.');
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        console.log('SERVER: No Authorization header or malformed. Sending 401.');
        return res.status(401).json({ message: 'No token provided or malformed.' });
    }

    const token = authHeader.replace('Bearer ', '');
    try {
        const decoded = jwt.verify(token, SECRET_KEY, { algorithms: ['HS512'] });
        req.user = decoded; // Attach decoded user info to request
        // console.log('SERVER: Token successfully verified. User:', req.user.username, 'ID:', req.user.userId);
        next();
    } catch (error) {
        console.error('SERVER ERROR: JWT Verification FAILED:', error.message);
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({ message: 'Token expired. Please log in again.' });
        }
        return res.status(401).json({ message: 'Invalid token.' });
    }
}
// --- END JWT Authentication Middleware ---

// --- Static pages ---
// Note: Ensure these file paths are correct relative to where backend.js runs.
// If your HTML files are in a 'public' directory, you'll need to adjust.
// Based on your image_4f7396.png, they are in the root alongside backend.js
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'home.html')));
app.get('/Login', (req, res) => res.sendFile(path.join(__dirname, 'Login.html')));
app.get('/Signup', (req, res) => res.sendFile(path.join(__dirname, 'Signup.html')));
app.get('/Event', (req, res) => res.sendFile(path.join(__dirname, 'EventRegister.html')));
app.get('/Home', (req, res) => res.sendFile(path.join(__dirname, 'userhome.html')));
app.get('/developers', (req, res) => res.sendFile(path.join(__dirname, 'developers.html')));
app.get('/data', (req, res) => res.sendFile(path.join(__dirname, 'data.html')));
app.get('/Submissions.html', (req, res) => res.sendFile(path.join(__dirname, 'Submissions.html')));
app.get('/script.js', (req, res) => res.sendFile(path.join(__dirname, 'script.js')));
app.get('/banner.jpg', (req, res) => res.sendFile(path.join(__dirname, 'banner.jpg')));
app.get('/claim.html', (req, res) => res.sendFile(path.join(__dirname, 'claim.html'))); // Unsure what this is, keeping it. Claimform.html is probably the main one.
app.get('/Claimform.html', (req, res) => res.sendFile(path.join(__dirname, 'Claimform.html')));
app.get('/LeaderBoard.html', (req, res) => res.sendFile(path.join(__dirname, 'LeaderBoard.html')));


// --- User Authentication Routes (DynamoDB Integrated) ---

// Signup
app.post('/signup', async (req, res) => {
    const { email, password, username, mobile } = req.body;
    try {
        // Check if username already exists using DynamoDB GSI
        const usernameCheck = await dynamodb.query({
            TableName: 'Users',
            IndexName: 'Username-index',
            KeyConditionExpression: 'Username = :username', // Use 'Username' as per your schema
            ExpressionAttributeValues: { ':username': username.toLowerCase() }
        }).promise();
        if (usernameCheck.Items && usernameCheck.Items.length > 0) {
            return res.status(400).json({ message: 'Username already in use' });
        }

        // Check if email already exists using DynamoDB GSI
        const emailCheck = await dynamodb.query({
            TableName: 'Users',
            IndexName: 'Email-index',
            KeyConditionExpression: 'Email = :email', // Use 'Email' as per your schema
            ExpressionAttributeValues: { ':email': email }
        }).promise();
        if (emailCheck.Items && emailCheck.Items.length > 0) {
            return res.status(400).json({ message: 'Email already in use' });
        }

        // Check if mobile already exists using DynamoDB GSI
        const mobileCheck = await dynamodb.query({
            TableName: 'Users',
            IndexName: 'Mobile-index',
            KeyConditionExpression: 'Mobile = :mobile', // Use 'Mobile' as per your schema
            ExpressionAttributeValues: { ':mobile': mobile }
        }).promise();
        if (mobileCheck.Items && mobileCheck.Items.length > 0) {
            return res.status(400).json({ message: 'Mobile no already in use' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = {
            UserId: uuidv4(),
            Email: email,
            Mobile: mobile,
            password: hashedPassword,
            Username: username.toLowerCase(), // Store with capital 'U' as per your schema
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString()
        };

        await dynamodb.put({
            TableName: 'Users',
            Item: newUser
        }).promise();

        res.status(201).json({ message: 'User created successfully' });
    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ message: 'Server error during signup: ' + error.message });
    }
});

// Login
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const result = await dynamodb.query({
            TableName: 'Users',
            IndexName: 'Email-index',
            KeyConditionExpression: 'Email = :email',
            ExpressionAttributeValues: { ':email': email }
        }).promise();

        const user = result.Items[0];
        if (!user) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        // Use user.Username (capital U) as stored in DB
        const token = jwt.sign({ userId: user.UserId, username: user.Username }, SECRET_KEY, { expiresIn: '1h', algorithm: 'HS512' });
        res.status(200).json({ token });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Server error during login: ' + error.message });
    }
});

// Validate token
app.post('/valid', (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ message: 'No token provided or malformed.' });
    }

    const token = authHeader.replace('Bearer ', '');
    try {
        const decoded = jwt.verify(token, SECRET_KEY, { algorithms: ['HS512'] });
        res.status(200).json({ userId: decoded.userId, username: decoded.username });
    } catch (error) {
        res.status(401).json({ message: error instanceof jwt.TokenExpiredError ? 'Token expired' : 'Invalid token' });
    }
});

// NEW: Get User Profile Details
app.get('/api/user-profile', authenticateUser, async (req, res) => {
    const userId = req.user.userId;
    try {
        const userResult = await dynamodb.get({
            TableName: 'Users',
            Key: { UserId: userId }
        }).promise();

        const user = userResult.Item;
        if (!user) {
            return res.status(404).json({ message: 'User profile not found.' });
        }

        // Return only necessary profile details, exclude password
        res.status(200).json({
            userId: user.UserId,
            username: user.Username, // Return Username with Capital 'U' as stored
            Email: user.Email,
            Mobile: user.Mobile
        });
    } catch (error) {
        console.error('SERVER ERROR: Failed to fetch user profile:', error);
        res.status(500).json({ message: 'Server error fetching user profile: ' + error.message });
    }
});


// --- Donation Routes (DynamoDB Integrated, with Base64 Images) ---

// File submission (donation)
app.post('/api/donate', authenticateUser, upload.single('image'), async (req, res) => {
    const { title, description, category, quantity, location } = req.body;
    const userId = req.user.userId;

    if (!req.file) {
        return res.status(400).json({ message: 'Image file is required for donation.' });
    }

    try {
        const imageFile = req.file;
        const imageDataBase64 = imageFile.buffer.toString('base64');
        const imageSizeKB = imageFile.buffer.length / 1024;

        const MAX_IMAGE_SIZE_KB_BASE64 = 60; // Adjusted for DynamoDB item size limits
        if (imageSizeKB > MAX_IMAGE_SIZE_KB_BASE64) {
            return res.status(400).json({ message: `Image file is too large. Max allowed: ${MAX_IMAGE_SIZE_KB_BASE64} KB.` });
        }

        const newDonation = {
            donationId: uuidv4(),
            userId: userId,
            title: title,
            description: description,
            category: category,
            quantity: parseInt(quantity),
            imageData: imageDataBase64,
            imageMimeType: imageFile.mimetype,
            status: 'available', // Default status: available
            postedAt: new Date().toISOString(),
            location: location ? JSON.parse(location) : null,
        };

        await dynamodb.put({
            TableName: 'Donations',
            Item: newDonation
        }).promise();

        res.status(201).json({ message: 'Donation submitted successfully!', donation: newDonation });

    } catch (error) {
        console.error('SERVER ERROR: Donation submission failed:', error);
        if (error.code === 'ValidationException' && error.message.includes('The item size has exceeded the maximum allowable size')) {
            return res.status(413).json({ message: 'Donation data (including image) is too large. Please use a smaller image.' });
        }
        res.status(500).json({ message: 'Server error during donation submission: ' + error.message });
    }
});

// Get all posts (for userhome.html - public feed)
app.get('/api/posts', async (req, res) => {
    try {
        // Query the GSI for 'available' donations, sorted by postedAt (most recent first)
        const result = await dynamodb.query({
            TableName: 'Donations',
            IndexName: 'StatusPostedAt-index',
            KeyConditionExpression: '#status = :statusValue',
            ExpressionAttributeNames: { '#status': 'status' },
            ExpressionAttributeValues: { ':statusValue': 'available' },
            ScanIndexForward: false // Get most recent first
        }).promise();

        res.status(200).json(result.Items);
    } catch (error) {
        console.error('SERVER ERROR: Failed to fetch public posts:', error);
        res.status(500).json({ message: 'Server error fetching public posts: ' + error.message });
    }
});

// Get my submissions (for Submissions.html - user's own donations)
app.get('/api/my-submissions', authenticateUser, async (req, res) => {
    const userId = req.user.userId;

    try {
        // Fetch donations posted by this user
        const myDonationsResult = await dynamodb.query({
            TableName: 'Donations',
            IndexName: 'userId-index',
            KeyConditionExpression: 'userId = :userId',
            ExpressionAttributeValues: { ':userId': userId },
            ScanIndexForward: false
        }).promise();

        const myDonations = myDonationsResult.Items;

        const donationsWithClaims = await Promise.all(myDonations.map(async (donation) => {
            const claimsResult = await dynamodb.query({
                TableName: 'Claims',
                IndexName: 'DonationId-index', // Use the GSI on Claims table
                KeyConditionExpression: 'donationId = :donationId',
                ExpressionAttributeValues: { ':donationId': donation.donationId }
            }).promise();

            // Attach claims info to the donation object
            // Sort claims by claimedAt (most recent first)
            const claims = claimsResult.Items.sort((a, b) => new Date(b.claimedAt) - new Date(a.claimedAt));

            // Enrich claims with claimer's full user details
            const enrichedClaims = await Promise.all(claims.map(async (claim) => {
                let claimerUsername = 'N/A';
                let claimerMobile = 'N/A';
                let claimerEmail = 'N/A';

                if (claim.claimerUserId) {
                    try {
                        const claimerUserResult = await dynamodb.get({
                            TableName: 'Users',
                            Key: { UserId: claim.claimerUserId }
                        }).promise();

                        if (claimerUserResult.Item) {
                            const userItem = claimerUserResult.Item;
                            // Ensure attribute names match EXACTLY with your DynamoDB Users table schema
                            claimerUsername = userItem.Username || 'N/A'; // Use Username with capital 'U'
                            claimerMobile = userItem.Mobile || 'N/A';
                            claimerEmail = userItem.Email || 'N/A';
                        }
                    } catch (userFetchError) {
                        console.error(`[ClaimsOnMyDonations] Error fetching user ${claim.claimerUserId}:`, userFetchError);
                    }
                }

                return {
                    ...claim,
                    claimerUsername: claimerUsername,
                    claimerMobile: claimerMobile,
                    claimerEmail: claimerEmail,
                    claimerAddress: claim.claimerAddress || 'N/A', // These are stored on the claim item itself
                    claimerState: claim.claimerState || 'N/A',
                    reasonForClaim: claim.reasonForClaim || 'No reason provided.'
                };
            }));

            donation.claims = enrichedClaims; // Assign the enriched claims back
            return donation;
        }));

        res.status(200).json(donationsWithClaims);
    } catch (error) {
        console.error('SERVER ERROR: Failed to fetch user submissions and their claims:', error);
        res.status(500).json({ message: 'Server error fetching user submissions: ' + error.message });
    }
});


// Submit a claim (UPDATED LOGIC - now accepts form fields)
app.post('/api/claim', authenticateUser, async (req, res) => {
    // donationId comes from hidden field, address, state, reasonForClaim from form
    const { donationId, address, state, reasonForClaim } = req.body;
    const claimerUserId = req.user.userId; // From JWT token

    if (!donationId || !address || !state) {
        return res.status(400).json({ message: 'Missing required claim details (donationId, address, state).' });
    }

    try {
        // 1. Verify donation existence and status
        const donationResult = await dynamodb.get({
            TableName: 'Donations',
            Key: { donationId: donationId }
        }).promise();

        const donation = donationResult.Item;
        if (!donation) {
            return res.status(404).json({ message: 'Donation not found.' });
        }
        if (donation.status !== 'available') {
            return res.status(400).json({ message: `Donation is not available for claim.` });
        }
        if (donation.userId === claimerUserId) {
            return res.status(400).json({ message: 'You cannot claim your own donation.' });
        }

        // 2. Check if this user already has a pending claim for this donation
        // We look for 'pending' status only. If they have a rejected one, they can claim again.
        const existingClaims = await dynamodb.query({
            TableName: 'Claims',
            IndexName: 'ClaimerUserId-ClaimStatus-index', // Use the GSI on Claims table
            KeyConditionExpression: 'claimerUserId = :claimerUserId AND claimStatus = :claimStatus', // Exact match 'pending'
            FilterExpression: 'donationId = :donationId', // Filter on donationId
            ExpressionAttributeValues: {
                ':claimerUserId': claimerUserId,
                ':claimStatus': 'pending', // Look for 'pending' claims
                ':donationId': donationId
            }
        }).promise();

        if (existingClaims.Items && existingClaims.Items.length > 0) {
            return res.status(400).json({ message: 'You already have a pending claim for this item.' });
        }

        // 3. Create a new claim in the Claims table
        const newClaim = {
            claimId: uuidv4(),
            donationId: donationId,
            donorUserId: donation.userId, // Store donor's ID for easy lookup
            claimerUserId: claimerUserId,
            claimStatus: 'pending', // Initial status
            claimedAt: new Date().toISOString(),
            // New fields from the claim form:
            claimerAddress: address,
            claimerState: state,
            reasonForClaim: reasonForClaim || '' // Optional field
        };

        await dynamodb.put({
            TableName: 'Claims',
            Item: newClaim
        }).promise();

        res.status(200).json({ message: 'Claim submitted successfully! The donor will review it.', claim: newClaim });

    } catch (error) {
        console.error('SERVER ERROR: Claim submission failed:', error);
        res.status(500).json({ message: 'Server error during claim submission: ' + error.message });
    }
});

// NEW: Accept a claim
app.post('/api/claims/accepted', authenticateUser, async (req, res) => {
    const { claimId, donationId } = req.body;
    const donorUserId = req.user.userId;

    if (!claimId || !donationId) {
        return res.status(400).json({ message: 'Claim ID and Donation ID are required.' });
    }

    try {
        // 1. Get the claim to verify donor and current status
        const claimResult = await dynamodb.get({
            TableName: 'Claims',
            Key: { claimId: claimId }
        }).promise();

        const claim = claimResult.Item;
        if (!claim) {
            return res.status(404).json({ message: 'Claim not found.' });
        }
        if (claim.donorUserId !== donorUserId) {
            return res.status(403).json({ message: 'You are not authorized to accept this claim.' });
        }
        if (claim.claimStatus !== 'pending') {
            return res.status(400).json({ message: `Claim is already ${claim.claimStatus}.` });
        }
        if (claim.donationId !== donationId) {
            return res.status(400).json({ message: 'Donation ID mismatch for claim.' });
        }

        // 2. Update claim status to 'accepted'
        await dynamodb.update({
            TableName: 'Claims',
            Key: { claimId: claimId },
            UpdateExpression: 'SET claimStatus = :newStatus, updatedAt = :updatedAt',
            ExpressionAttributeValues: {
                ':newStatus': 'accepted',
                ':updatedAt': new Date().toISOString()
            }
        }).promise();

        // 3. Update the associated donation status to 'claimed' (or 'fulfilled')
        // Important: You might want to consider if a donation can have multiple claims.
        // For simplicity, here we assume one acceptance makes the donation 'claimed'.
        await dynamodb.update({
            TableName: 'Donations',
            Key: { donationId: donationId },
            UpdateExpression: 'SET #status = :newStatus, updatedAt = :updatedAt',
            ExpressionAttributeNames: { '#status': 'status' }, // 'status' is a reserved word, use alias
            ExpressionAttributeValues: {
                ':newStatus': 'claimed',
                ':updatedAt': new Date().toISOString()
            }
        }).promise();

        // 4. (Optional but recommended) Reject all other pending claims for this donation
        const otherPendingClaimsResult = await dynamodb.query({
            TableName: 'Claims',
            IndexName: 'DonationId-index', // Use the GSI on Claims table
            KeyConditionExpression: 'donationId = :donationId',
            FilterExpression: 'claimStatus = :pendingStatus AND claimId <> :acceptedClaimId',
            ExpressionAttributeValues: {
                ':donationId': donationId,
                ':pendingStatus': 'pending',
                ':acceptedClaimId': claimId
            }
        }).promise();

        if (otherPendingClaimsResult.Items && otherPendingClaimsResult.Items.length > 0) {
            await Promise.all(otherPendingClaimsResult.Items.map(async (otherClaim) => {
                await dynamodb.update({
                    TableName: 'Claims',
                    Key: { claimId: otherClaim.claimId },
                    UpdateExpression: 'SET claimStatus = :newStatus, updatedAt = :updatedAt',
                    ExpressionAttributeValues: {
                        ':newStatus': 'rejected',
                        ':updatedAt': new Date().toISOString()
                    }
                }).promise();
            }));
        }


        res.status(200).json({ message: 'Claim accepted successfully! Donation status updated.' });

    } catch (error) {
        console.error('SERVER ERROR: Failed to accept claim:', error);
        res.status(500).json({ message: 'Server error accepting claim: ' + error.message });
    }
});

// NEW: Reject a claim
app.post('/api/claims/rejected', authenticateUser, async (req, res) => {
    const { claimId, donationId } = req.body;
    const donorUserId = req.user.userId;

    if (!claimId || !donationId) {
        return res.status(400).json({ message: 'Claim ID and Donation ID are required.' });
    }

    try {
        // 1. Get the claim to verify donor and current status
        const claimResult = await dynamodb.get({
            TableName: 'Claims',
            Key: { claimId: claimId }
        }).promise();

        const claim = claimResult.Item;
        if (!claim) {
            return res.status(404).json({ message: 'Claim not found.' });
        }
        if (claim.donorUserId !== donorUserId) {
            return res.status(403).json({ message: 'You are not authorized to reject this claim.' });
        }
        if (claim.claimStatus !== 'pending') {
            return res.status(400).json({ message: `Claim is already ${claim.claimStatus}.` });
        }
        if (claim.donationId !== donationId) {
            return res.status(400).json({ message: 'Donation ID mismatch for claim.' });
        }

        // 2. Update claim status to 'rejected'
        await dynamodb.update({
            TableName: 'Claims',
            Key: { claimId: claimId },
            UpdateExpression: 'SET claimStatus = :newStatus, updatedAt = :updatedAt',
            ExpressionAttributeValues: {
                ':newStatus': 'rejected',
                ':updatedAt': new Date().toISOString()
            }
        }).promise();

        res.status(200).json({ message: 'Claim rejected successfully!' });

    } catch (error) {
        console.error('SERVER ERROR: Failed to reject claim:', error);
        res.status(500).json({ message: 'Server error rejecting claim: ' + error.message });
    }
});


// app.listen(PORT, () => {
//     console.log(`Server running on port ${PORT}`);
//     console.log(`Access frontend at http://localhost:${PORT}`);
// });

app.listen(5000, '0.0.0.0', () => {
  console.log('Server running at http://0.0.0.0:5000');
});
