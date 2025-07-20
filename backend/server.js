// Load environment variables from .env file
require('dotenv').config();

// Import necessary modules
const express = require('express');
const http = require('http'); // Node.js built-in HTTP module
const { Server } = require('socket.io'); // Socket.IO server
const { MongoClient, ObjectId } = require('mongodb'); // MongoDB driver, added ObjectId for user ID
const path = require('path'); // Node.js built-in path module
const cors = require('cors'); // For Cross-Origin Resource Sharing
const bcrypt = require('bcryptjs'); // For password hashing

// Initialize Express app
const app = express();
// Create an HTTP server instance from the Express app
const server = http.createServer(app);
// Initialize Socket.IO server, allowing connections from your frontend domain
const io = new Server(server, {
    cors: {
        // This origin allows your HTML files opened directly in the browser to connect.
        // In a production environment, replace "*" with your actual frontend domain(s).
        origin: "*",
        methods: ["GET", "POST"]
    }
});

// MongoDB connection URI
// For local MongoDB, this is typically 'mongodb://localhost:27017'
// We'll use a specific database name, e.g., 'campusconnect_db'
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/campusconnect_db';
const DB_NAME = process.env.DB_NAME || 'campusconnect_db';

let db; // Variable to hold our MongoDB database instance

// Admin credentials from environment variables
const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

// Function to connect to MongoDB
async function connectDB() {
    try {
        const client = new MongoClient(MONGODB_URI);
        await client.connect();
        db = client.db(DB_NAME);
        console.log('Connected to MongoDB successfully!');

        // Ensure default rooms exist and are public
        const roomsCollection = db.collection('rooms');
        await roomsCollection.updateOne(
            { name: 'General Chat' },
            { $setOnInsert: { name: 'General Chat', type: 'public', createdAt: new Date() } },
            { upsert: true }
        );
        await roomsCollection.updateOne(
            { name: 'Confession Wall' },
            { $setOnInsert: { name: 'Confession Wall', type: 'public', createdAt: new Date() } },
            { upsert: true }
        );
        console.log('Ensured default rooms exist.');

    } catch (error) {
        console.error('Failed to connect to MongoDB:', error);
        process.exit(1); // Exit process if database connection fails
    }
}

// Middleware for admin authentication (simple token check for now)
const authenticateAdmin = (req, res, next) => {
    // For a real app, you'd use JWTs and verify them here
    // For this local demo, we'll just check if a token exists (sent by admin.html's JS)
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Access Denied: No token provided.' });
    }

    // In a real app, verify the token's validity and expiration
    // For this simple demo, any non-empty token after successful login is "valid"
    if (token === 'admin-authenticated-token') { // This token is hardcoded in admin.html's JS
        next();
    } else {
        res.status(403).json({ message: 'Access Denied: Invalid token.' });
    }
};


// Enable CORS for all Express routes (important for frontend communication)
app.use(cors());
// Middleware to parse JSON request bodies
app.use(express.json());

// Serve static files (your frontend HTML, CSS, JS, images)
// This makes your C:\CampusConnect folder accessible via the server
// The '..' goes up one directory from 'backend' to 'CampusConnect'
app.use(express.static(path.join(__dirname, '..')));

// Basic API route for testing server status
app.get('/api/status', (req, res) => {
    res.json({ status: 'Server is running', database: db ? 'Connected' : 'Disconnected' });
});

// --- User Authentication Routes ---

// Register User Route
app.post('/api/register', async (req, res) => {
    const { fullName, username, email, password } = req.body;

    // Basic validation
    if (!fullName || !username || !email || !password) {
        return res.status(400).json({ message: 'All fields are required.' });
    }

    // NUTECH email validation
    if (!email.endsWith('@nutech.edu.pk')) {
        return res.status(400).json({ message: 'Only NUTECH university emails (@nutech.edu.pk) are allowed for registration.' });
    }

    try {
        const usersCollection = db.collection('users');

        // Check if username or email already exists
        const existingUser = await usersCollection.findOne({ $or: [{ username: username }, { email: email }] });
        if (existingUser) {
            return res.status(409).json({ message: 'Username or email already exists.' });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10); // 10 is the salt rounds

        // Create new user document
        const newUser = {
            fullName,
            username,
            email,
            password: hashedPassword,
            profilePicUrl: '', // Default empty, can be updated later
            bio: '',           // Default empty, can be updated later
            joinedRooms: ['General Chat', 'Confession Wall'], // Default public rooms
            isBanned: false, // New field: default to not banned
            createdAt: new Date()
        };

        // Insert user into MongoDB
        const result = await usersCollection.insertOne(newUser);
        console.log('New user registered:', result.insertedId);

        res.status(201).json({ message: 'Registration successful!', userId: result.insertedId });

    } catch (error) {
        console.error('Error during registration:', error);
        res.status(500).json({ message: 'Server error during registration.' });
    }
});

// Login User Route
app.post('/api/login', async (req, res) => {
    const { identifier, password } = req.body; // 'identifier' can be username or email

    if (!identifier || !password) {
        return res.status(400).json({ message: 'Identifier (username/email) and password are required.' });
    }

    try {
        const usersCollection = db.collection('users');

        // Find user by username or email
        const user = await usersCollection.findOne({ $or: [{ username: identifier }, { email: identifier }] });
        if (!user) {
            return res.status(401).json({ message: 'Invalid credentials.' });
        }

        // Compare provided password with hashed password
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ message: 'Invalid credentials.' });
        }

        res.status(200).json({
            message: 'Login successful!',
            user: {
                id: user._id, // MongoDB ObjectId
                fullName: user.fullName,
                username: user.username,
                email: user.email,
                profilePicUrl: user.profilePicUrl,
                bio: user.bio,
                joinedRooms: user.joinedRooms || ['General Chat', 'Confession Wall'], // Ensure this is sent
                isBanned: user.isBanned || false // Send ban status
            }
        });

    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ message: 'Server error during login.' });
    }
});

// --- User Profile Routes ---

// Get User Profile by ID
app.get('/api/profile/:userId', async (req, res) => {
    const { userId } = req.params;

    if (!userId) {
        return res.status(400).json({ message: 'User ID is required.' });
    }

    try {
        const usersCollection = db.collection('users');
        // Find user by ObjectId
        const user = await usersCollection.findOne({ _id: new ObjectId(userId) });

        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }

        // Return profile data, excluding sensitive information like password
        res.status(200).json({
            id: user._id,
            fullName: user.fullName,
            username: user.username,
            email: user.email,
            profilePicUrl: user.profilePicUrl,
            bio: user.bio,
            joinedRooms: user.joinedRooms || ['General Chat', 'Confession Wall'], // Ensure this is sent
            isBanned: user.isBanned || false, // Send ban status
            createdAt: user.createdAt
        });

    } catch (error) {
        console.error('Error fetching user profile:', error);
        // Handle invalid ObjectId format
        if (error.name === 'BSONTypeError') {
            return res.status(400).json({ message: 'Invalid User ID format.' });
        }
        res.status(500).json({ message: 'Server error fetching profile.' });
    }
});

// Update User Profile
app.post('/api/profile/update', async (req, res) => {
    const { userId, fullName, username, email, bio, profilePicUrl } = req.body;

    if (!userId) {
        return res.status(400).json({ message: 'User ID is required for update.' });
    }

    try {
        const usersCollection = db.collection('users');

        // Check if the user exists
        const existingUser = await usersCollection.findOne({ _id: new ObjectId(userId) });
        if (!existingUser) {
            return res.status(404).json({ message: 'User not found.' });
        }

        // Prepare update object
        const updateFields = {};
        if (fullName !== undefined) updateFields.fullName = fullName;
        if (bio !== undefined) updateFields.bio = bio;
        if (profilePicUrl !== undefined) updateFields.profilePicUrl = profilePicUrl; // Now we handle this field

        // Handle username update: check for uniqueness if changed
        if (username !== undefined && username !== existingUser.username) {
            const usernameExists = await usersCollection.findOne({ username: username, _id: { $ne: new ObjectId(userId) } });
            if (usernameExists) {
                return res.status(409).json({ message: 'Username already taken.' });
            }
            updateFields.username = username;
        }

        // Handle email update: check for uniqueness and NUTECH domain if changed
        // NOTE: Frontend has email as readonly, but backend still validates if sent
        if (email !== undefined && email !== existingUser.email) {
            if (!email.endsWith('@nutech.edu.pk')) {
                return res.status(400).json({ message: 'Only NUTECH university emails (@nutech.edu.pk) are allowed.' });
            }
            const emailExists = await usersCollection.findOne({ email: email, _id: { $ne: new ObjectId(userId) } });
            if (emailExists) {
                return res.status(409).json({ message: 'Email already in use by another account.' });
            }
            updateFields.email = email;
        }

        // Perform the update
        const result = await usersCollection.updateOne(
            { _id: new ObjectId(userId) },
            { $set: updateFields }
        );

        // Fetch the updated user to send back the latest data
        const updatedUser = await usersCollection.findOne({ _id: new ObjectId(userId) });
        res.status(200).json({
            message: 'Profile updated successfully!',
            user: {
                id: updatedUser._id,
                fullName: updatedUser.fullName,
                username: updatedUser.username,
                email: updatedUser.email,
                profilePicUrl: updatedUser.profilePicUrl,
                bio: updatedUser.bio,
                joinedRooms: updatedUser.joinedRooms || ['General Chat', 'Confession Wall'],
                isBanned: updatedUser.isBanned || false // Send ban status
            }
        });

    } catch (error) {
        console.error('Error updating user profile:', error);
        if (error.name === 'BSONTypeError') {
            return res.status(400).json({ message: 'Invalid User ID format.' });
        }
        res.status(500).json({ message: 'Server error updating profile.' });
    }
});

// --- Admin Panel Routes ---

// Admin Login
app.post('/api/admin/login', async (req, res) => {
    const { username, password } = req.body;

    if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
        // In a real app, generate a JWT token here
        res.status(200).json({ message: 'Admin login successful!', token: 'admin-authenticated-token' }); // Simple token
    } else {
        res.status(401).json({ message: 'Invalid admin credentials.' });
    }
});

// Admin: Create New Room
app.post('/api/admin/rooms', authenticateAdmin, async (req, res) => {
    const { name, type } = req.body; // type can be 'public' or 'private'

    if (!name || !type) {
        return res.status(400).json({ message: 'Room name and type are required.' });
    }
    if (!['public', 'private'].includes(type)) {
        return res.status(400).json({ message: 'Invalid room type. Must be "public" or "private".' });
    }

    try {
        const roomsCollection = db.collection('rooms');
        const existingRoom = await roomsCollection.findOne({ name: name });
        if (existingRoom) {
            return res.status(409).json({ message: 'Room with this name already exists.' });
        }

        const newRoom = {
            name,
            type,
            createdAt: new Date()
        };
        await roomsCollection.insertOne(newRoom);
        res.status(201).json({ message: `Room "${name}" created successfully as ${type}.` });
    } catch (error) {
        console.error('Error creating room:', error);
        res.status(500).json({ message: 'Server error creating room.' });
    }
});

// Admin: Get All Rooms (for chat.html to fetch and admin.html to display)
app.get('/api/rooms', async (req, res) => {
    try {
        const roomsCollection = db.collection('rooms');
        const rooms = await roomsCollection.find({}).toArray();
        res.status(200).json({ rooms });
    } catch (error) {
        console.error('Error fetching rooms:', error);
        res.status(500).json({ message: 'Server error fetching rooms.' });
    }
});

// Admin: Delete Room
app.delete('/api/admin/rooms/:roomName', authenticateAdmin, async (req, res) => {
    const { roomName } = req.params;

    // Prevent deletion of default public rooms
    if (roomName === 'General Chat' || roomName === 'Confession Wall') {
        return res.status(403).json({ message: `Cannot delete default public room: "${roomName}".` });
    }

    try {
        const roomsCollection = db.collection('rooms');
        const usersCollection = db.collection('users');
        const messagesCollection = db.collection('messages');
        const roomRequestsCollection = db.collection('roomRequests');

        // 1. Delete the room from the 'rooms' collection
        const roomDeleteResult = await roomsCollection.deleteOne({ name: roomName });
        if (roomDeleteResult.deletedCount === 0) {
            return res.status(404).json({ message: `Room "${roomName}" not found.` });
        }

        // 2. Remove the room from 'joinedRooms' array of all users
        await usersCollection.updateMany(
            { joinedRooms: roomName },
            { $pull: { joinedRooms: roomName } }
        );

        // 3. Delete all messages associated with this room
        await messagesCollection.deleteMany({ room: roomName });

        // 4. Delete any pending/rejected requests for this room
        await roomRequestsCollection.deleteMany({ roomName: roomName });

        res.status(200).json({ message: `Room "${roomName}" and all associated data deleted successfully.` });

    } catch (error) {
        console.error('Error deleting room:', error);
        res.status(500).json({ message: 'Server error deleting room.' });
    }
});


// Admin: Submit Room Join Request (from user)
app.post('/api/rooms/request-join', async (req, res) => {
    const { userId, username, userEmail, roomName } = req.body;

    if (!userId || !username || !userEmail || !roomName) {
        return res.status(400).json({ message: 'User ID, username, email, and room name are required.' });
    }

    try {
        const roomsCollection = db.collection('rooms');
        const room = await roomsCollection.findOne({ name: roomName });
        if (!room) {
            return res.status(400).json({ message: 'This room does not exist.' });
        }
        if (room.type === 'public') {
             return res.status(400).json({ message: 'This is a public room and does not require a join request. You can join directly.' });
        }


        const roomRequestsCollection = db.collection('roomRequests');
        // Check for existing pending request by this user for this room
        const existingRequest = await roomRequestsCollection.findOne({ userId: new ObjectId(userId), roomName: roomName, status: 'pending' });
        if (existingRequest) {
            return res.status(409).json({ message: 'You already have a pending request for this room.' });
        }

        const newRequest = {
            userId: new ObjectId(userId),
            username,
            userEmail,
            roomName,
            status: 'pending', // 'pending', 'approved', 'rejected'
            requestedAt: new Date()
        };
        await roomRequestsCollection.insertOne(newRequest);
        res.status(200).json({ message: 'Your request to join the room has been submitted for approval.' });

    } catch (error) {
        console.error('Error submitting room join request:', error);
        if (error.name === 'BSONTypeError') {
            return res.status(400).json({ message: 'Invalid User ID format.' });
        }
        res.status(500).json({ message: 'Server error submitting request.' });
    }
});

// Admin: Get Pending Room Join Requests
app.get('/api/admin/room-requests', authenticateAdmin, async (req, res) => {
    try {
        const roomRequestsCollection = db.collection('roomRequests');
        const pendingRequests = await roomRequestsCollection.find({ status: 'pending' }).toArray();
        res.status(200).json({ requests: pendingRequests });
    } catch (error) {
        console.error('Error fetching pending room requests:', error);
        res.status(500).json({ message: 'Server error fetching requests.' });
    }
});

// Admin: Approve/Reject Room Join Request
app.post('/api/admin/room-requests/:requestId/action', authenticateAdmin, async (req, res) => {
    const { requestId } = req.params;
    const { action, reason } = req.body; // action: 'approve' or 'reject'

    if (!action || !['approve', 'reject'].includes(action)) {
        return res.status(400).json({ message: 'Invalid action specified.' });
    }

    try {
        const roomRequestsCollection = db.collection('roomRequests');
        const usersCollection = db.collection('users');
        const userNotificationsCollection = db.collection('userNotifications'); // New collection for notifications

        const request = await roomRequestsCollection.findOne({ _id: new ObjectId(requestId) });
        if (!request) {
            return res.status(404).json({ message: 'Room request not found.' });
        }
        if (request.status !== 'pending') {
            return res.status(400).json({ message: `Request already ${request.status}.` });
        }

        if (action === 'approve') {
            // Add room to user's joinedRooms
            await usersCollection.updateOne(
                { _id: request.userId },
                { $addToSet: { joinedRooms: request.roomName } } // $addToSet prevents duplicates
            );
            // Update request status
            await roomRequestsCollection.updateOne(
                { _id: new ObjectId(requestId) },
                { $set: { status: 'approved', processedAt: new Date() } }
            );
            // Add a notification for the user
            await userNotificationsCollection.insertOne({
                userId: request.userId,
                type: 'room_request_status',
                message: `Your request to join "${request.roomName}" has been approved. You can now join this room.`,
                status: 'unread',
                createdAt: new Date(),
                relatedRoom: request.roomName
            });

            res.status(200).json({ message: `Request for ${request.username} to join ${request.roomName} approved.` });
        } else if (action === 'reject') {
            // Update request status with reason
            await roomRequestsCollection.updateOne(
                { _id: new ObjectId(requestId) },
                { $set: { status: 'rejected', reason: reason || 'No reason provided.', processedAt: new Date() } }
            );
            // Add a notification for the user with the reason
            await userNotificationsCollection.insertOne({
                userId: request.userId,
                type: 'room_request_status',
                message: `Your request to join "${request.roomName}" has been rejected. Reason: ${reason || 'No reason provided.'}`,
                status: 'unread',
                createdAt: new Date(),
                relatedRoom: request.roomName,
                rejectionReason: reason || 'No reason provided.'
            });
            res.status(200).json({ message: `Request for ${request.username} to join ${request.roomName} rejected.` });
        }

    } catch (error) {
        console.error('Error processing room request action:', error);
        if (error.name === 'BSONTypeError') {
            return res.status(400).json({ message: 'Invalid Request ID format.' });
        }
        res.status(500).json({ message: 'Server error processing request.' });
    }
});

// User: Get Notifications
app.get('/api/user/notifications/:userId', async (req, res) => {
    const { userId } = req.params;
    if (!userId) {
        return res.status(400).json({ message: 'User ID is required.' });
    }
    try {
        const userNotificationsCollection = db.collection('userNotifications');
        const notifications = await userNotificationsCollection.find({ userId: new ObjectId(userId), status: 'unread' }).sort({ createdAt: -1 }).toArray();
        res.status(200).json({ notifications });
    } catch (error) {
        console.error('Error fetching user notifications:', error);
        if (error.name === 'BSONTypeError') {
            return res.status(400).json({ message: 'Invalid User ID format.' });
        }
        res.status(500).json({ message: 'Server error fetching notifications.' });
    }
});

// User: Mark Notification as Read
app.post('/api/user/notifications/mark-read', async (req, res) => {
    const { notificationId, userId } = req.body;
    if (!notificationId || !userId) {
        return res.status(400).json({ message: 'Notification ID and User ID are required.' });
    }
    try {
        const userNotificationsCollection = db.collection('userNotifications');
        await userNotificationsCollection.updateOne(
            { _id: new ObjectId(notificationId), userId: new ObjectId(userId) },
            { $set: { status: 'read', readAt: new Date() } }
        );
        res.status(200).json({ message: 'Notification marked as read.' });
    } catch (error) {
        console.error('Error marking notification as read:', error);
        if (error.name === 'BSONTypeError') {
            return res.status(400).json({ message: 'Invalid ID format.' });
        }
        res.status(500).json({ message: 'Server error marking notification as read.' });
    }
});

// Admin: Get All Users
app.get('/api/admin/users', authenticateAdmin, async (req, res) => {
    try {
        const usersCollection = db.collection('users');
        // Fetch all users, but exclude their passwords for security
        const users = await usersCollection.find({}, { projection: { password: 0 } }).toArray();
        res.status(200).json({ users });
    } catch (error) {
        console.error('Error fetching all users:', error);
        res.status(500).json({ message: 'Server error fetching users.' });
    }
});

// Admin: Ban/Unban User
app.post('/api/admin/users/:userId/ban', authenticateAdmin, async (req, res) => {
    const { userId } = req.params;
    const { isBanned, reason } = req.body; // isBanned: true/false, reason: optional string

    if (typeof isBanned !== 'boolean') {
        return res.status(400).json({ message: 'Invalid ban status provided.' });
    }

    try {
        const usersCollection = db.collection('users');
        const userNotificationsCollection = db.collection('userNotifications');

        const userObjectId = new ObjectId(userId);
        const user = await usersCollection.findOne({ _id: userObjectId });

        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }

        // Prevent banning the admin account itself (if admin is a regular user in DB)
        // This check assumes admin is NOT stored as a regular user in 'users' collection.
        // If admin is stored as a user, you'd need a more robust way to identify the admin user.
        // For now, we assume admin is separate.

        await usersCollection.updateOne(
            { _id: userObjectId },
            { $set: { isBanned: isBanned } }
        );

        let notificationMessage;
        if (isBanned) {
            notificationMessage = `You have been banned from Campus Connect. Reason: ${reason || 'No reason provided.'} Please contact muneebaamir2006@gmail.com to get unbanned.`;
        } else {
            notificationMessage = `You have been unbanned from Campus Connect. You can now access all features.`;
        }

        await userNotificationsCollection.insertOne({
            userId: userObjectId,
            type: 'ban_status',
            message: notificationMessage,
            status: 'unread',
            createdAt: new Date(),
            banStatus: isBanned,
            reason: reason || ''
        });

        res.status(200).json({ message: `User ${user.username} has been ${isBanned ? 'banned' : 'unbanned'}.` });

    } catch (error) {
        console.error('Error banning/unbanning user:', error);
        if (error.name === 'BSONTypeError') {
            return res.status(400).json({ message: 'Invalid User ID format.' });
        }
        res.status(500).json({ message: 'Server error processing ban/unban request.' });
    }
});


// --- Socket.IO connection handling ---
// Store connected users by their socket ID and username
const connectedUsers = {};

io.on('connection', (socket) => {
    console.log('A user connected:', socket.id);

    // When a user joins a room, they also send their username and user ID
    socket.on('joinRoom', async (roomName, username, userId) => {
        // If userId is provided (from authenticated user), store it
        if (userId) {
            socket.data.userId = userId;
        }
        socket.data.username = username; // Store username on the socket object
        connectedUsers[socket.id] = username; // Store in our connectedUsers map

        const usersCollection = db.collection('users');
        const roomsCollection = db.collection('rooms');
        const userNotificationsCollection = db.collection('userNotifications'); // Access notifications collection

        try {
            // Check if the user is banned FIRST
            if (userId) {
                const user = await usersCollection.findOne({ _id: new ObjectId(userId) });
                if (user && user.isBanned) {
                    // Send a specific message to the banned user and prevent further actions
                    socket.emit('banned', {
                        message: `You are currently banned from Campus Connect. Reason: ${user.banReason || 'No reason provided.'} Please contact muneebaamir2006@gmail.com to get unbanned.`,
                        contactEmail: 'muneebaamir2006@gmail.com'
                    });
                    console.log(`Banned user ${username} (${userId}) attempted to join room ${roomName}.`);
                    socket.disconnect(true); // Disconnect the socket for banned users
                    return; // Stop further processing for banned users
                }
            }


            const room = await roomsCollection.findOne({ name: roomName });
            if (!room) {
                console.warn(`Attempted to join non-existent room: ${roomName}`);
                socket.emit('message', { user: 'Admin', text: `Room "${roomName}" does not exist.`, timestamp: new Date(), room: roomName });
                return;
            }

            // Check if the room is private and if the user is authorized
            if (room.type === 'private') {
                if (!userId) { // Should not happen if frontend enforces login
                    socket.emit('message', { user: 'Admin', text: `Please log in to join private rooms.`, timestamp: new Date(), room: roomName });
                    return;
                }
                const user = await usersCollection.findOne({ _id: new ObjectId(userId) });
                // Check if user exists AND if joinedRooms array contains the roomName
                if (!user || !user.joinedRooms || !user.joinedRooms.includes(roomName)) {
                    // Fetch any relevant rejection notifications for this user and room
                    const rejectionNotification = await userNotificationsCollection.findOne({
                        userId: new ObjectId(userId),
                        relatedRoom: roomName,
                        type: 'room_request_status',
                        status: 'rejected' // Only show rejected ones here
                    });

                    let rejectionMessage = `You are not approved to join "${roomName}". Please request access from the admin.`;
                    if (rejectionNotification && rejectionNotification.rejectionReason) {
                        rejectionMessage += ` Reason: ${rejectionNotification.rejectionReason}`;
                    }
                    socket.emit('message', { user: 'Admin', text: rejectionMessage, timestamp: new Date(), room: roomName });
                    return;
                }
            }

            // User is authorized or room is public, proceed to join
            socket.join(roomName);
            console.log(`${username} (${socket.id}) joined room: ${roomName}`);

            // Welcome message to the user who joined
            socket.emit('message', { user: 'Admin', text: `Welcome to the ${roomName} room!`, timestamp: new Date(), room: roomName });
            // Notify others in the room
            socket.to(roomName).emit('message', { user: 'Admin', text: `${username} has joined the room.`, timestamp: new Date(), room: roomName });

            // --- Fetch and send chat history for the joined room ---
            const messagesCollection = db.collection('messages');
            // Find messages for the specific room, sorted by timestamp
            const chatHistory = await messagesCollection.find({ room: roomName }).sort({ timestamp: 1 }).toArray();
            socket.emit('chatHistory', chatHistory); // Send history to the joining user
            console.log(`Sent ${chatHistory.length} messages to ${username} in room ${roomName}`);

            // --- Fetch and send unread notifications to the user ---
            const unreadNotifications = await userNotificationsCollection.find({ userId: new ObjectId(userId), status: 'unread' }).sort({ createdAt: 1 }).toArray();
            if (unreadNotifications.length > 0) {
                socket.emit('notifications', unreadNotifications);
                console.log(`Sent ${unreadNotifications.length} unread notifications to ${username}`);
            }

        } catch (error) {
            console.error('Error during joinRoom:', error);
            socket.emit('message', { user: 'Admin', text: `Error joining room: ${roomName}.`, timestamp: new Date(), room: roomName });
        }
    });

    // Handle chat messages
    socket.on('chatMessage', async (messageData) => {
        const { text, username, room, userId } = messageData;

        // Check if the user sending the message is banned
        if (userId) {
            const usersCollection = db.collection('users');
            const user = await usersCollection.findOne({ _id: new ObjectId(userId) });
            if (user && user.isBanned) {
                console.log(`Banned user ${username} (${userId}) attempted to send message in room ${room}.`);
                // Optionally send a message back to the banned user's client
                socket.emit('banned', {
                    message: `You cannot send messages because you are banned. Please contact muneebaamir2006@gmail.com to get unbanned.`,
                    contactEmail: 'muneebaamir2006@gmail.com'
                });
                return; // Prevent message from being processed
            }
        }

        console.log(`Message from ${username} in room ${room}: ${text}`);

        // Create the message object to be broadcasted and saved
        const messageToBroadcast = {
            user: username, // Use the actual username
            text: text,
            room: room,
            timestamp: new Date() // Add server-side timestamp
        };

        // Broadcast the message to all clients in the specific room
        io.to(room).emit('message', messageToBroadcast);

        // Save message to MongoDB (optional, but good for history)
        if (db) {
            db.collection('messages').insertOne(messageToBroadcast)
                .then(result => console.log('Message saved to DB:', result.insertedId))
                .catch(err => console.error('Error saving message to DB:', err));
        }
    });

    // Handle user leaving a room (optional, but good for cleanup)
    socket.on('leaveRoom', (roomName) => {
        socket.leave(roomName);
        console.log(`${socket.data.username} (${socket.id}) left room: ${roomName}`);
        // Notify others in the room
        socket.to(roomName).emit('message', { user: 'Admin', text: `${socket.data.username} has left the room.`, timestamp: new Date(), room: roomName });
    });

    // Handle disconnection
    socket.on('disconnect', () => {
        const username = connectedUsers[socket.id] || 'A user'; // Get username if available
        console.log(`${username} (${socket.id}) disconnected.`);
        delete connectedUsers[socket.id]; // Remove from connected users map
        // Optionally, notify rooms that this user disconnected
        // (This would require iterating through rooms the user was in)
    });
});

// Start the server
const PORT = process.env.PORT || 3000;
server.listen(PORT, async () => {
    console.log(`Server running on port ${PORT}`);
    await connectDB(); // Connect to MongoDB when the server starts
});

// Graceful shutdown
process.on('SIGINT', async () => {
    console.log('Server shutting down...');
    if (db) {
        // Ensure to close the client correctly
        // The db object is the database instance, which has a client property
        await db.client.close();
        console.log('MongoDB connection closed.');
    }
    server.close(() => {
        console.log('HTTP server closed.');
        process.exit(0);
    });
});
