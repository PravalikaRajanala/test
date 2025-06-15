// app.js - Node.js Backend for TuneJam
// This server handles Socket.IO real-time communication for jam sessions,
// serves static files, and provides API endpoints for song search and logout.

// Load environment variables from .env file in development.
// On Vercel, environment variables are automatically available.
require('dotenv').config();

// --- Module Imports ---
const express = require('express');
const http = require('http'); // Required for Socket.IO server creation
const { Server } = require('socket.io');
const cors = require('cors'); // For handling Cross-Origin Resource Sharing
const path = require('path'); // For path manipulation
const fs = require('fs'); // For reading file system (e.g., manifest.json)
const admin = require('firebase-admin'); // Firebase Admin SDK
const cookieParser = require('cookie-parser'); // For parsing cookies
const { getFirestore } = require('firebase-admin/firestore'); // Import getFirestore explicitly

// --- Firebase Admin SDK Initialization ---
const firebaseAdminCredentials = process.env.FIREBASE_ADMIN_CREDENTIALS_JSON;
let db = null;
let auth = null;

if (!firebaseAdminCredentials) {
    console.error("CRITICAL ERROR: FIREBASE_ADMIN_CREDENTIALS_JSON environment variable is NOT SET. Firebase Admin SDK will not be initialized. Jam features will NOT work.");
} else {
    try {
        const serviceAccount = JSON.parse(firebaseAdminCredentials);
        admin.initializeApp({
            credential: admin.credential.cert(serviceAccount)
        });
        db = getFirestore(); // Initialize Firestore
        auth = admin.auth(); // Initialize Auth
        console.log("Firebase Admin SDK initialized SUCCESSFULLY. Firestore and Auth instances available.");
    } catch (e) {
        console.error("CRITICAL ERROR: Error parsing FIREBASE_ADMIN_CREDENTIALS_JSON or initializing Firebase Admin SDK:", e.message, e.stack);
        console.error("Please ensure the FIREBASE_ADMIN_CREDENTIALS_JSON environment variable contains a single-line, valid JSON string for your Firebase service account.");
    }
}

// --- Express App Setup ---
const app = express();
const server = http.createServer(app);

// Configure CORS for Express
app.use(cors({
    origin: '*', // Allows all origins for development. Restrict in production.
    methods: ['GET', 'POST'],
    credentials: true, // Allow cookies to be sent
}));

// Use Express's built-in body parser for JSON requests
app.use(express.json());
app.use(cookieParser()); // Use cookie-parser middleware

// --- Session Cookie Configuration ---
const SESSION_COOKIE_NAME = '__session';
const SESSION_COOKIE_OPTIONS = {
    maxAge: 60 * 60 * 24 * 5 * 1000, // 5 days
    httpOnly: true, // Prevent client-side JavaScript from accessing the cookie
    secure: process.env.NODE_ENV === 'production', // Only send over HTTPS in production
    sameSite: 'Lax', // Protect against CSRF
    path: '/'
};

// --- Authentication Middleware ---
/**
 * Middleware to verify Firebase session cookie and authenticate requests.
 */
async function authenticateSession(req, res, next) {
    const sessionCookie = req.cookies[SESSION_COOKIE_NAME] || '';

    if (!sessionCookie) {
        console.log("No session cookie found, redirecting to login.");
        return res.redirect('/login');
    }

    try {
        const decodedClaims = await auth.verifySessionCookie(sessionCookie, true); // Check for revocation
        req.user = decodedClaims; // Attach user claims to the request object
        console.log(`User ${req.user.uid} authenticated via session cookie.`);
        next();
    } catch (error) {
        console.warn("Session cookie verification failed:", error.code, error.message);
        // Session cookie is invalid, revoked, or expired. Clear it and redirect.
        res.clearCookie(SESSION_COOKIE_NAME);
        return res.redirect('/login');
    }
}

// --- Socket.IO Setup ---
const io = new Server(server, {
    cors: {
        origin: '*',
        methods: ['GET', 'POST'],
        credentials: true,
    },
    pingTimeout: 60000,
});

// --- In-Memory State for Jam Sessions (Server-Side - ephemeral on serverless) ---
// Note: This 'activeJamSessions' object is primarily for quick lookup of participant nicknames
// and host_sid on a per-server instance basis. The true source of truth is Firestore.
const activeJamSessions = {};

// --- Serve Static Files ---
app.use(express.static(path.join(__dirname)));

// Basic root route - PROTECTED
app.get('/', authenticateSession, (req, res) => {
    // If the user is authenticated, serve the main app (index.html)
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Route for login page - Publicly accessible
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'login.html'));
});

// Route for register page - Publicly accessible
app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'register.html'));
});

// Dashboard route - Redirects to main app if authenticated
app.get('/dashboard', authenticateSession, (req, res) => {
    res.redirect('/'); // Redirect to the main app after successful login/registration
});

// Load the hosted songs manifest once on startup for search functionality
let hostedSongsManifest = [];
const hostedSongsManifestPath = path.join(__dirname, 'hosted_songs_manifest.json');
try {
    if (fs.existsSync(hostedSongsManifestPath)) {
        hostedSongsManifest = JSON.parse(fs.readFileSync(hostedSongsManifestPath, 'utf8'));
        console.log(`Loaded ${hostedSongsManifest.length} songs from hosted_songs_manifest.json`);
    } else {
        console.warn("hosted_songs_manifest.json not found at:", hostedSongsManifestPath);
    }
} catch (error) {
    console.error("Error loading hosted_songs_manifest.json:", error);
}

// --- API Endpoints ---

// Login API endpoint
app.post('/login', async (req, res) => {
    if (!auth) {
        return res.status(500).json({ error: "Firebase Auth not initialized on server." });
    }
    const idToken = req.body.id_token;
    if (!idToken) {
        return res.status(400).json({ error: "ID token is required." });
    }

    try {
        const decodedIdToken = await auth.verifyIdToken(idToken);
        // Create session cookie
        const sessionCookie = await auth.createSessionCookie(idToken, SESSION_COOKIE_OPTIONS);
        res.cookie(SESSION_COOKIE_NAME, sessionCookie, SESSION_COOKIE_OPTIONS);
        console.log(`Login successful for UID: ${decodedIdToken.uid}. Session cookie set.`);
        return res.status(200).json({ status: 'success' });
    } catch (error) {
        console.error("Error during login (ID token verification or session cookie creation):", error.message);
        return res.status(401).json({ error: "Unauthorized: Invalid ID token or session creation failed." });
    }
});

// Register API endpoint
app.post('/register', async (req, res) => {
    if (!auth || !db) {
        return res.status(500).json({ error: "Firebase services not initialized on server." });
    }
    const { id_token, username, favorite_artist, favorite_genre, experience_level } = req.body;

    if (!id_token || !username) {
        return res.status(400).json({ error: "ID token and username are required for registration." });
    }

    try {
        const decodedIdToken = await auth.verifyIdToken(id_token);
        const uid = decodedIdToken.uid;

        // Store additional user profile data in Firestore
        await db.collection('users').doc(uid).set({
            username: username,
            email: decodedIdToken.email,
            favorite_artist: favorite_artist || null,
            favorite_genre: favorite_genre || null,
            experience_level: experience_level || null,
            createdAt: admin.firestore.FieldValue.serverTimestamp()
        }, { merge: true }); // Use merge to update existing if user somehow pre-exists

        // Create and set session cookie
        const sessionCookie = await auth.createSessionCookie(id_token, SESSION_COOKIE_OPTIONS);
        res.cookie(SESSION_COOKIE_NAME, sessionCookie, SESSION_COOKIE_OPTIONS);
        console.log(`Registration successful for UID: ${uid}. Profile saved to Firestore. Session cookie set.`);
        return res.status(200).json({ status: 'success' });
    } catch (error) {
        console.error("Error during registration:", error.message);
        // Firebase Admin SDK errors related to token verification
        return res.status(401).json({ error: `Registration failed: ${error.message}` });
    }
});

// Logout API endpoint
app.get('/logout', (req, res) => {
    console.log("Logout endpoint hit. Clearing session cookie.");
    res.clearCookie(SESSION_COOKIE_NAME);
    res.redirect('/login'); // Redirect to login page after logout
});

app.get('/search_hosted_mp3s', (req, res) => {
    const query = req.query.query ? req.query.query.toLowerCase() : '';
    if (!query) {
        return res.json([]);
    }
    const results = hostedSongsManifest.filter(song =>
        song.title.toLowerCase().includes(query) ||
        (song.artist && song.artist.toLowerCase().includes(query))
    );
    res.json(results);
});


// --- Socket.IO Event Handlers ---

function generateShortUniqueId() {
    return Math.random().toString(36).substring(2, 8).toUpperCase();
}

async function getJamSessionFromFirestore(jamId) {
    if (!db) {
        console.error("Firestore DB not initialized. Cannot fetch jam session data.");
        return null;
    }
    try {
        const docRef = db.collection('jam_sessions').doc(jamId);
        const doc = await docRef.get();
        if (doc.exists) {
            return doc.data();
        }
        return null;
    } catch (error) {
        console.error(`Error fetching jam session ${jamId} from Firestore:`, error);
        return null;
    }
}

async function updateJamSessionInFirestore(jamId, data) {
    if (!db) {
        console.error("Firestore DB not initialized. Cannot update jam session data.");
        return;
    }
    try {
        const docRef = db.collection('jam_sessions').doc(jamId);
        await docRef.set(data, { merge: true });
        console.log(`Jam session ${jamId} updated in Firestore.`);
    } catch (error) {
        console.error(`Error updating jam session ${jamId} in Firestore:`, error);
    }
}

// Map Socket ID to User ID (for server-side tracking, though Firestore is primary)
const socketIdToUserId = {};

io.on('connection', (socket) => {
    console.log(`A user connected: ${socket.id}`);
    const userId = socket.handshake.query.userId;
    if (userId) {
        socketIdToUserId[socket.id] = userId;
        console.log(`Socket ${socket.id} mapped to User ID: ${userId}`);
    } else {
        console.warn(`Socket ${socket.id} connected without a User ID.`);
    }

    socket.on('create_session', async (data) => {
        if (!db) {
            socket.emit('join_failed', { message: "Server is not configured for Firebase. Cannot create jam session." });
            return;
        }
        const { jam_name, nickname, userId } = data; // Ensure userId is received
        if (!userId) {
            socket.emit('join_failed', { message: "User not authenticated. Please log in." });
            return;
        }

        let jamId = generateShortUniqueId();
        let jamDoc = await getJamSessionFromFirestore(jamId);
        while (jamDoc && jamDoc.is_active) {
            jamId = generateShortUniqueId();
            jamDoc = await getJamSessionFromFirestore(jamId);
        }

        const newJam = {
            id: jamId,
            name: jam_name || `Jam Session ${jamId}`,
            host_sid: socket.id,
            host_user_id: userId, // Store host's Firebase User ID
            participants: { [socket.id]: nickname }, // Map socket ID to nickname
            playlist: [],
            playback_state: {
                current_track_index: 0,
                current_playback_time: 0,
                is_playing: false,
                timestamp: admin.firestore.FieldValue.serverTimestamp()
            },
            is_active: true,
            created_at: admin.firestore.FieldValue.serverTimestamp()
        };

        try {
            // Store in Firestore within the artifacts/{appId}/public/data/jam_sessions path
            // The `appId` must be dynamically accessed from the environment or a configuration
            // For this backend, assuming 'default-app-id' as a placeholder or it needs to be injected.
            // For Vercel/similar environments, you might pass APP_ID as an env var.
            const appIdFromEnv = process.env.APP_ID || 'default-app-id'; // Use an env var or a hardcoded default
            const docRef = db.collection('artifacts').doc(appIdFromEnv).collection('public').doc('data').collection('jam_sessions').doc(jamId);
            await docRef.set(newJam);

            socket.join(jamId);
            // Update in-memory for immediate use (ephemeral on serverless, primarily for `io.to` targeting)
            activeJamSessions[jamId] = { host_sid: socket.id, participants: { [socket.id]: nickname } };
            
            // Generate shareable link using VERCEL_URL if available, otherwise localhost
            const shareableLink = `${process.env.VERCEL_URL || `http://localhost:${process.env.PORT || 3000}`}/?jam_id=${jamId}`;
            
            socket.emit('session_created', {
                jam_id: jamId,
                jam_name: newJam.name,
                is_host: true,
                participants: newJam.participants,
                nickname_used: nickname,
                shareable_link: shareableLink
            });
            console.log(`Jam session ${jamId} created by ${nickname} (${socket.id}).`);
        } catch (error) {
            console.error("Error creating session:", error);
            socket.emit('join_failed', { message: "Failed to create jam session." });
        }
    });

    socket.on('join_session', async (data) => {
        if (!db) {
            socket.emit('join_failed', { message: "Server is not configured for Firebase. Cannot join jam session." });
            return;
        }
        const { jam_id, nickname, userId } = data; // Ensure userId is received
        if (!userId) {
            socket.emit('join_failed', { message: "User not authenticated. Please log in." });
            return;
        }

        const appIdFromEnv = process.env.APP_ID || 'default-app-id';
        const docRef = db.collection('artifacts').doc(appIdFromEnv).collection('public').doc('data').collection('jam_sessions').doc(jam_id);
        const jamDoc = await docRef.get();

        if (!jamDoc.exists || !jamDoc.data().is_active) {
            socket.emit('join_failed', { message: `Jam session ${jam_id} not found or is inactive.` });
            return;
        }
        const jamDocData = jamDoc.data();
        
        const updatedParticipants = { ...jamDocData.participants, [socket.id]: nickname };
        await docRef.update({ participants: updatedParticipants });

        socket.join(jam_id);
        if (!activeJamSessions[jam_id]) {
             activeJamSessions[jam_id] = { host_sid: jamDocData.host_sid, participants: updatedParticipants };
        } else {
            activeJamSessions[jam_id].participants = updatedParticipants;
        }

        socket.emit('session_join_success', {
            jam_id: jam_id,
            jam_name: jamDocData.name,
            playlist: jamDocData.playlist || [],
            playback_state: jamDocData.playback_state,
            current_track_index: jamDocData.playback_state.current_track_index,
            current_playback_time: jamDocData.playback_state.current_playback_time,
            is_playing: jamDocData.playback_state.is_playing,
            last_synced_at: jamDocData.playback_state.timestamp ? jamDocData.playback_state.timestamp.seconds : 0,
            participants: updatedParticipants,
            nickname_used: nickname
        });
        io.to(jam_id).emit('update_participants', { jam_id: jam_id, participants: updatedParticipants });
        console.log(`${nickname} (${socket.id}) joined jam session ${jam_id}.`);
    });

    socket.on('sync_playback_state', async (data) => {
        if (!db) {
            console.error("Firestore DB not initialized. Cannot sync playback state.");
            return;
        }
        const { jam_id, current_track_index, current_playback_time, is_playing, playlist } = data;
        const appIdFromEnv = process.env.APP_ID || 'default-app-id';
        const docRef = db.collection('artifacts').doc(appIdFromEnv).collection('public').doc('data').collection('jam_sessions').doc(jam_id);
        const jamDoc = await docRef.get();

        if (!jamDoc.exists || jamDoc.data().host_sid !== socket.id || !jamDoc.data().is_active) {
            console.warn(`Attempted sync from non-host or inactive session: ${socket.id} for jam ${jam_id}`);
            return;
        }
        const playbackState = {
            current_track_index: current_track_index,
            current_playback_time: current_playback_time,
            is_playing: is_playing,
            timestamp: admin.firestore.FieldValue.serverTimestamp()
        };
        try {
            await docRef.update({
                playlist: playlist,
                playback_state: playbackState
            });
            console.log(`Jam ${jam_id} playback state synced by host ${socket.id}.`);
        } catch (error) {
            console.error(`Error syncing playback state for jam ${jam_id}:`, error);
        }
    });

    socket.on('add_song_to_jam', async (data) => {
        if (!db) {
            console.error("Firestore DB not initialized. Cannot add song to jam.");
            return;
        }
        const { jam_id, song } = data;
        const appIdFromEnv = process.env.APP_ID || 'default-app-id';
        const docRef = db.collection('artifacts').doc(appIdFromEnv).collection('public').doc('data').collection('jam_sessions').doc(jam_id);
        const jamDoc = await docRef.get();

        if (!jamDoc.exists || jamDoc.data().host_sid !== socket.id || !jamDoc.data().is_active) {
            console.warn(`Attempted to add song from non-host or inactive session: ${socket.id} for jam ${jam_id}`);
            return;
        }
        const updatedPlaylist = [...(jamDoc.data().playlist || []), song];
        try {
            await docRef.update({ playlist: updatedPlaylist });
            console.log(`Song "${song.title}" added to jam ${jam_id} by host ${socket.id}.`);
        } catch (error) {
            console.error(`Error adding song to jam ${jam_id}:`, error);
        }
    });

    socket.on('remove_song_from_jam', async (data) => {
        if (!db) {
            console.error("Firestore DB not initialized. Cannot remove song from jam.");
            return;
        }
        const { jam_id, song_id } = data;
        const appIdFromEnv = process.env.APP_ID || 'default-app-id';
        const docRef = db.collection('artifacts').doc(appIdFromEnv).collection('public').doc('data').collection('jam_sessions').doc(jam_id);
        const jamDoc = await docRef.get();

        if (!jamDoc.exists || jamDoc.data().host_sid !== socket.id || !jamDoc.data().is_active) {
            console.warn(`Attempted to remove song from non-host or inactive session: ${socket.id} for jam ${jam_id}`);
            return;
        }
        const originalPlaylist = jamDoc.data().playlist || [];
        const updatedPlaylist = originalPlaylist.filter(song => song.id !== song_id);

        if (updatedPlaylist.length === originalPlaylist.length) {
            console.warn(`Song with ID ${song_id} not found in jam ${jam_id}'s playlist.`);
            return;
        }
        try {
            await docRef.update({ playlist: updatedPlaylist });
            console.log(`Song with ID ${song_id} removed from jam ${jam_id} by host ${socket.id}.`);
        } catch (error) {
            console.error(`Error removing song from jam ${jam_id}:`, error);
        }
    });

    socket.on('leave_session', async (data) => {
        if (!db) {
            console.error("Firestore DB not initialized. Cannot leave jam session.");
            return;
        }
        const { jam_id } = data;
        const appIdFromEnv = process.env.APP_ID || 'default-app-id';
        const docRef = db.collection('artifacts').doc(appIdFromEnv).collection('public').doc('data').collection('jam_sessions').doc(jam_id);
        const jamDoc = await docRef.get();

        if (!jamDoc.exists || !jamDoc.data().is_active) {
            console.warn(`Attempted to leave inactive or non-existent jam: ${jam_id}`);
            return;
        }
        const jamDocData = jamDoc.data();
        const updatedParticipants = { ...jamDocData.participants };
        const leftNickname = updatedParticipants[socket.id];
        delete updatedParticipants[socket.id];

        socket.leave(jam_id);
        let updatedIsActive = jamDocData.is_active;

        if (jamDocData.host_sid === socket.id) {
            console.log(`Host ${leftNickname} (${socket.id}) is leaving jam ${jam_id}.`);
            if (Object.keys(updatedParticipants).length > 0) {
                const newHostSocketId = Object.keys(updatedParticipants)[0];
                console.log(`Assigning new host for jam ${jamId}: ${newHostSocketId}`);
                await docRef.update({
                    host_sid: newHostSocketId,
                    participants: updatedParticipants
                });
                io.to(jam_id).emit('update_participants', { jam_id: jam_id, participants: updatedParticipants });
                io.to(jam_id).emit('session_ended', { message: `Host changed for Jam Session "${jamDocData.name}".` });
            } else {
                updatedIsActive = false;
                await docRef.update({ is_active: false, participants: updatedParticipants });
                io.to(jam_id).emit('session_ended', { message: `Jam Session "${jamDocData.name}" has ended as host left.` });
                delete activeJamSessions[jam_id];
            }
        } else {
            await docRef.update({ participants: updatedParticipants });
            io.to(jam_id).emit('update_participants', { jam_id: jam_id, participants: updatedParticipants });
            console.log(`${leftNickname} (${socket.id}) left jam session ${jam_id}.`);
        }
    });

    socket.on('disconnect', async () => {
        console.log(`User disconnected: ${socket.id}`);
        delete socketIdToUserId[socket.id];

        if (!db) {
            console.warn("Firestore DB not initialized. Skipping disconnect logic for jam sessions.");
            return;
        }
        // Query for jams where this socket was a participant or host
        const appIdFromEnv = process.env.APP_ID || 'default-app-id';
        const jamSessionsCollection = db.collection('artifacts').doc(appIdFromEnv).collection('public').doc('data').collection('jam_sessions');
        
        // Find jams where the disconnected socket was a participant
        const participantQuery = jamSessionsCollection.where(`participants.${socket.id}`, '!=', null).where('is_active', '==', true);
        const hostQuery = jamSessionsCollection.where('host_sid', '==', socket.id).where('is_active', '==', true);

        const participantDocs = await participantQuery.get();
        const hostDocs = await hostQuery.get();

        const allRelevantDocs = [...participantDocs.docs, ...hostDocs.docs];
        const processedJamIds = new Set(); // To avoid processing the same jam twice

        for (const docSnapshot of allRelevantDocs) {
            const jamId = docSnapshot.id;
            if (processedJamIds.has(jamId)) continue; // Skip if already processed
            processedJamIds.add(jamId);

            const jamDocData = docSnapshot.data();

            const updatedParticipants = { ...jamDocData.participants };
            const leftNickname = updatedParticipants[socket.id] || "A participant"; // Fallback nickname
            delete updatedParticipants[socket.id];

            let newHostSocketId = jamDocData.host_sid;
            let updatedIsActive = jamDocData.is_active;
            let disconnectMessage = `${leftNickname} has left the session.`;

            if (jamDocData.host_sid === socket.id) {
                if (Object.keys(updatedParticipants).length > 0) {
                    newHostSocketId = Object.keys(updatedParticipants)[0];
                    console.log(`Host ${leftNickname} (${socket.id}) disconnected from jam ${jamId}. New host: ${newHostSocketId}`);
                    // Notify remaining participants about host change and potentially re-sync
                    io.to(jamId).emit('session_ended', { message: `Host changed for Jam Session "${jamDocData.name}". New host: ${updatedParticipants[newHostSocketId] || 'Unknown'}.` });
                } else {
                    updatedIsActive = false;
                    console.log(`Host ${leftNickname} (${socket.id}) disconnected. Jam ${jamId} ended.`);
                    disconnectMessage = `Jam Session "${jamDocData.name}" has ended as host disconnected.`;
                    delete activeJamSessions[jamId];
                }
            } else {
                console.log(`${leftNickname} (${socket.id}) disconnected from jam ${jamId}.`);
            }

            // Update the Firestore document
            await jamSessionsCollection.doc(jamId).update({
                participants: updatedParticipants,
                host_sid: newHostSocketId,
                is_active: updatedIsActive
            });

            // Emit updates to clients
            if (updatedIsActive) {
                io.to(jamId).emit('update_participants', { jam_id: jamId, participants: updatedParticipants });
            } else {
                io.to(jamId).emit('session_ended', { message: disconnectMessage });
            }
        }
    });
});

// --- Error Handling (for Express) ---
app.use((err, req, res, next) => {
    console.error("Express error caught:", err.stack);
    res.status(500).send('An internal server error occurred.');
});

// IMPORTANT for Vercel: Export the Express app
// Vercel wraps this exported app and handles the server listening.
module.exports = app;

// The app.listen() call below is ONLY for local development.
// It will be ignored by Vercel's serverless environment.
// For local testing, you can uncomment this block.
/*
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Server running LOCALLLY on port ${PORT}`);
    console.log(`Access the application locally at: http://localhost:${PORT}`);
    console.log("For Vercel deployment, remember to set FIREBASE_ADMIN_CREDENTIALS_JSON and VERCEL_URL.");
});
*/
