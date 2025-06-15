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
        origin: '*', // Allow all origins for development. Restrict in production to your frontend URL.
        methods: ['GET', 'POST'],
        credentials: true,
    },
    pingTimeout: 60000,
});

// --- In-Memory State for Jam Sessions (Server-Side - ephemeral on serverless) ---
// Note: This 'activeJamSessions' object is primarily for quick lookup of participant nicknames
// and host_sid on a per-server instance basis. The true source of truth is Firestore.
const activeJamSessions = {};

// Get Firestore collection reference (after db is initialized)
let jamSessionsCollection;
if (db) {
    // APP_ID is usually passed as an environment variable in Vercel.
    // Ensure it's defined in your Vercel project settings.
    const appId = process.env.APP_ID || 'default-app-id'; // Fallback for local development
    jamSessionsCollection = db.collection(`artifacts/${appId}/public/data/jam_sessions`);
    console.log(`Firestore collection path: artifacts/${appId}/public/data/jam_sessions`);
} else {
    console.error("Firestore DB not initialized. Jam session features will be limited.");
}


// --- Utility Functions for Firestore (Backend) ---
/**
 * Fetches a jam session document from Firestore.
 * @param {string} jamId
 * @returns {Promise<FirebaseFirestore.DocumentData|null>}
 */
async function getJamSessionFromFirestore(jamId) {
    if (!jamSessionsCollection) return null;
    try {
        const doc = await jamSessionsCollection.doc(jamId).get();
        if (doc.exists) {
            return { id: doc.id, ...doc.data() };
        }
        return null;
    } catch (error) {
        console.error(`Error fetching jam session ${jamId} from Firestore:`, error);
        return null;
    }
}

/**
 * Updates a jam session document in Firestore.
 * @param {string} jamId
 * @param {object} updates
 * @returns {Promise<void>}
 */
async function updateJamSessionInFirestore(jamId, updates) {
    if (!jamSessionsCollection) {
        console.error("Firestore collection not initialized. Cannot update jam session.");
        return;
    }
    try {
        await jamSessionsCollection.doc(jamId).update(updates);
        console.log(`Firestore document ${jamId} updated.`);
    } catch (error) {
        console.error(`Error updating jam session ${jamId} in Firestore:`, error);
    }
}

/**
 * Adds a new jam session document to Firestore.
 * @param {string} jamName
 * @param {string} hostId
 * @param {string} hostNickname
 * @param {Array<Object>} playlist
 * @returns {Promise<string|null>} The new jam ID or null on error.
 */
async function createJamSessionInFirestore(jamName, hostId, hostNickname, playlist) {
    if (!jamSessionsCollection) return null;
    try {
        const newJamRef = await jamSessionsCollection.add({
            name: jamName,
            host_id: hostId,
            host_sid: null, // Will be updated when host connects via socket
            participants: [{ user_id: hostId, nickname: hostNickname, is_host: true }],
            current_song: null,
            current_time: 0,
            is_playing: false,
            playlist: playlist,
            created_at: admin.firestore.FieldValue.serverTimestamp(),
            is_active: true // Mark session as active
        });
        console.log(`New jam session created in Firestore with ID: ${newJamRef.id}`);
        return newJamRef.id;
    } catch (error) {
        console.error("Error creating jam session in Firestore:", error);
        return null;
    }
}

// --- Serve Static Files ---
// This serves all static files from the root directory.
// Vercel's build process will often handle explicit routes in vercel.json
// more directly, but this serves as a general fallback for other static assets.
app.use(express.static(path.join(__dirname)));


// --- Routes ---

// Basic root route - PROTECTED by authentication middleware
// Only authenticated users can access index.html
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

// API endpoint for user login
app.post('/api/login', async (req, res) => {
    const { idToken } = req.body; // Firebase ID token from client-side authentication

    if (!db || !auth) {
        return res.status(500).json({ success: false, message: "Firebase Admin SDK not initialized on server." });
    }

    if (!idToken) {
        return res.status(400).json({ success: false, message: "ID token is required." });
    }

    const expiresIn = 60 * 60 * 24 * 5 * 1000; // 5 days

    try {
        // Create a session cookie
        const sessionCookie = await auth.createSessionCookie(idToken, { expiresIn });
        // Set the session cookie on the response
        res.cookie(SESSION_COOKIE_NAME, sessionCookie, SESSION_COOKIE_OPTIONS);
        res.json({ success: true, message: "Logged in successfully!" });
    } catch (error) {
        console.error("Error creating session cookie:", error);
        res.status(401).json({ success: false, message: "Authentication failed. Please try again." });
    }
});

// API endpoint for user logout
app.post('/api/logout', (req, res) => {
    res.clearCookie(SESSION_COOKIE_NAME);
    res.json({ success: true, message: "Logged out successfully." });
});

// Load the hosted songs manifest once on startup for search functionality
// This will be accessible via /hosted_songs_manifest.json as a static file
// due to vercel.json configuration and app.use(express.static),
// but we also load it here for direct server-side access/search.
let hostedSongsManifest = [];
const hostedSongsManifestPath = path.join(__dirname, 'hosted_songs_manifest.json');
try {
    if (fs.existsSync(hostedSongsManifestPath)) {
        hostedSongsManifest = JSON.parse(fs.readFileSync(hostedSongsManifestPath, 'utf8'));
        console.log("Loaded hosted songs manifest on startup. Songs:", hostedSongsManifest.length);
    } else {
        console.warn("hosted_songs_manifest.json not found at:", hostedSongsManifestPath);
    }
} catch (error) {
    console.error("Error loading hosted_songs_manifest.json:", error);
}

// API endpoint to search hosted MP3s
app.get('/search_hosted_mp3s', (req, res) => {
    const query = req.query.q ? req.query.q.toLowerCase() : '';
    if (!hostedSongsManifest || hostedSongsManifest.length === 0) {
        return res.status(500).json({ message: "Hosted songs manifest not loaded or empty." });
    }
    const filteredSongs = hostedSongsManifest.filter(song =>
        song.title.toLowerCase().includes(query) ||
        (song.artist && song.artist.toLowerCase().includes(query))
    );
    res.json(filteredSongs);
});


// --- Socket.IO Event Handlers ---
io.on('connection', (socket) => {
    console.log('User connected:', socket.id);

    // Store user_id and nickname associated with socket for quick lookup
    socket.on('register_user', ({ user_id, nickname }) => {
        socket.userId = user_id;
        socket.nickname = nickname;
        console.log(`Socket ${socket.id} registered as User ID: ${user_id}, Nickname: ${nickname}`);
    });

    socket.on('create_jam', async (data) => {
        if (!db || !auth) {
            socket.emit('error_message', { message: "Server Firebase not initialized. Cannot create jam." });
            return;
        }

        const { jam_name, nickname, user_id, current_playlist } = data;
        if (!jam_name || !nickname || !user_id) {
            socket.emit('error_message', { message: "Jam name, nickname, and user ID are required to create a jam." });
            return;
        }

        // Ensure current_playlist is an array of objects with necessary fields
        const cleanedPlaylist = (current_playlist || []).map(song => ({
            id: song.id,
            title: song.title,
            artist: song.artist,
            url: song.url,
            thumbnail: song.thumbnail,
            duration: song.duration
        }));

        try {
            const jamId = await createJamSessionInFirestore(jam_name, user_id, nickname, cleanedPlaylist);
            if (jamId) {
                // Update Firestore with the host's socket ID after successful creation
                await updateJamSessionInFirestore(jamId, { host_sid: socket.id });

                socket.join(jamId);
                activeJamSessions[jamId] = {
                    name: jam_name,
                    host_id: user_id,
                    host_sid: socket.id,
                    participants: [{ user_id: user_id, nickname: nickname, is_host: true }],
                    current_song: cleanedPlaylist.length > 0 ? cleanedPlaylist[0] : null,
                    current_time: 0,
                    is_playing: false,
                    playlist: cleanedPlaylist,
                    is_active: true
                };
                socket.jamId = jamId; // Associate jamId with the socket

                socket.emit('jam_created', {
                    jam_id: jamId,
                    jam_name: jam_name,
                    host_id: user_id,
                    host_sid: socket.id,
                    participants: activeJamSessions[jamId].participants
                });
                console.log(`Jam session "${jam_name}" created by ${nickname} (${user_id}) with ID ${jamId}`);
            } else {
                socket.emit('error_message', { message: "Failed to create jam session in Firestore." });
            }
        } catch (error) {
            console.error("Server error creating jam:", error);
            socket.emit('error_message', { message: `Server error creating jam: ${error.message}` });
        }
    });

    socket.on('join_jam', async (data) => {
        if (!db || !auth) {
            socket.emit('error_message', { message: "Server Firebase not initialized. Cannot join jam." });
            return;
        }

        const { jam_id, nickname, user_id } = data;
        if (!jam_id || !nickname || !user_id) {
            socket.emit('error_message', { message: "Jam ID, nickname, and user ID are required to join a jam." });
            return;
        }

        try {
            const jamData = await getJamSessionFromFirestore(jam_id);

            if (!jamData || !jamData.is_active) {
                socket.emit('error_message', { message: "Jam session not found or is no longer active." });
                return;
            }

            // Check if user is already a participant
            const isAlreadyParticipant = jamData.participants.some(p => p.user_id === user_id);

            let updatedParticipants = [...jamData.participants];
            let participantRole = 'participant';

            if (!isAlreadyParticipant) {
                updatedParticipants.push({ user_id: user_id, nickname: nickname, is_host: false });
                await updateJamSessionInFirestore(jam_id, { participants: updatedParticipants });
            } else {
                // If user is rejoining, update their nickname if it changed
                const existingParticipant = updatedParticipants.find(p => p.user_id === user_id);
                if (existingParticipant && existingParticipant.nickname !== nickname) {
                    existingParticipant.nickname = nickname;
                    await updateJamSessionInFirestore(jam_id, { participants: updatedParticipants });
                }
                if (existingParticipant && existingParticipant.is_host) {
                    participantRole = 'host';
                }
            }

            socket.join(jam_id);
            socket.jamId = jam_id; // Associate jamId with the socket
            socket.userId = user_id; // Store user ID
            socket.nickname = nickname; // Store nickname
            socket.isHost = (participantRole === 'host'); // Store host status

            // Update in-memory state
            activeJamSessions[jam_id] = {
                name: jamData.name,
                host_id: jamData.host_id,
                host_sid: jamData.host_sid,
                participants: updatedParticipants, // Use the updated list
                current_song: jamData.current_song,
                current_time: jamData.current_time,
                is_playing: jamData.is_playing,
                playlist: jamData.playlist || [],
                is_active: jamData.is_active
            };

            socket.emit('joined_jam', {
                jam_id: jam_id,
                jam_name: jamData.name,
                host_id: jamData.host_id,
                participants: updatedParticipants,
                current_song: jamData.current_song,
                current_time: jamData.current_time,
                is_playing: jamData.is_playing,
                is_active: jamData.is_active
            });

            // If the host is joining or rejoining, update their socket ID in Firestore
            if (user_id === jamData.host_id) {
                await updateJamSessionInFirestore(jam_id, { host_sid: socket.id });
                activeJamSessions[jam_id].host_sid = socket.id; // Update in-memory
                socket.isHost = true; // Mark this socket as the host's
                console.log(`Host ${nickname} (${user_id}) rejoined jam ${jam_id}. Host SID updated.`);
            }

            // Broadcast updated participant list to everyone in the jam
            io.to(jam_id).emit('update_participants', { jam_id: jam_id, participants: updatedParticipants });

            console.log(`${nickname} (${user_id}) joined jam ${jam_id}.`);

        } catch (error) {
            console.error("Server error joining jam:", error);
            socket.emit('error_message', { message: `Server error joining jam: ${error.message}` });
        }
    });

    socket.on('rejoin_jam', async ({ jam_id, user_id, nickname }) => {
        // This is primarily for reconnects, ensuring socket.jamId and socket.userId are set.
        // Full state sync comes from Firestore listener on client side.
        if (!jam_id || !user_id || !nickname) {
            console.warn(`Rejoin attempt missing data: jam_id=${jam_id}, user_id=${user_id}, nickname=${nickname}`);
            return;
        }

        try {
            const jamData = await getJamSessionFromFirestore(jam_id);
            if (jamData && jamData.is_active) {
                socket.join(jam_id);
                socket.jamId = jam_id;
                socket.userId = user_id;
                socket.nickname = nickname;

                // Update participant list with latest socket ID if they are already in the list
                let updatedParticipants = [...jamData.participants];
                const participantIndex = updatedParticipants.findIndex(p => p.user_id === user_id);

                if (participantIndex > -1) {
                    updatedParticipants[participantIndex].socket_id = socket.id; // Store current socket ID
                    updatedParticipants[participantIndex].nickname = nickname; // Update nickname if changed
                } else {
                    // This scenario shouldn't happen if they are "rejoining" but good to handle
                    updatedParticipants.push({ user_id, nickname, is_host: false, socket_id: socket.id });
                }

                // If the rejoining user is the host, update the host_sid in Firestore
                if (jamData.host_id === user_id) {
                    await updateJamSessionInFirestore(jam_id, { host_sid: socket.id, participants: updatedParticipants });
                    console.log(`Host ${nickname} (${user_id}) reconnected to jam ${jam_id}. Host SID updated.`);
                } else {
                    await updateJamSessionInFirestore(jam_id, { participants: updatedParticipants });
                }

                // Update in-memory state
                activeJamSessions[jam_id] = {
                    ...jamData, // Keep existing Firestore data
                    participants: updatedParticipants,
                    host_sid: jamData.host_id === user_id ? socket.id : jamData.host_sid // Update host_sid if host reconnected
                };

                // Broadcast updated participant list to everyone in the jam
                io.to(jam_id).emit('update_participants', { jam_id: jam_id, participants: updatedParticipants });
                console.log(`${nickname} (${user_id}) reconnected to jam ${jam_id}.`);
            } else {
                console.log(`Rejoin failed for jam ${jam_id}. Jam not found or inactive.`);
                socket.emit('session_ended', { message: 'The jam session is no longer active or does not exist.' });
            }
        } catch (error) {
            console.error("Error during rejoin_jam:", error);
            socket.emit('error_message', { message: `Rejoin failed: ${error.message}` });
        }
    });

    // Host actions (only emit if the socket's userId is the current jam's host_id)
    socket.on('host_song_change', async (data) => {
        const { jam_id, song, current_time } = data;
        const jamData = await getJamSessionFromFirestore(jam_id);
        if (jamData && jamData.host_id === socket.userId) { // Ensure only host can trigger
            io.to(jam_id).emit('song_change', { jam_id, song, current_time });
            // Update Firestore with the new song
            await updateJamSessionInFirestore(jam_id, {
                current_song: song,
                current_time: current_time,
                is_playing: true // Assuming song change implies play
            });
            activeJamSessions[jam_id].current_song = song;
            activeJamSessions[jam_id].current_time = current_time;
            activeJamSessions[jam_id].is_playing = true;
            console.log(`Host ${socket.userId} changed song in jam ${jam_id} to ${song.title}`);
        } else {
            socket.emit('error_message', { message: "Only the host can change songs." });
        }
    });

    socket.on('host_play_state_change', async (data) => {
        const { jam_id, is_playing, current_time } = data;
        const jamData = await getJamSessionFromFirestore(jam_id);
        if (jamData && jamData.host_id === socket.userId) { // Ensure only host can trigger
            io.to(jam_id).emit('play_state_change', { jam_id, is_playing, current_time });
            // Update Firestore with the new play state
            await updateJamSessionInFirestore(jam_id, { is_playing, current_time });
            activeJamSessions[jam_id].is_playing = is_playing;
            activeJamSessions[jam_id].current_time = current_time;
            console.log(`Host ${socket.userId} changed play state in jam ${jam_id} to ${is_playing}`);
        } else {
            socket.emit('error_message', { message: "Only the host can change play state." });
        }
    });

    socket.on('host_seek', async (data) => {
        const { jam_id, current_time } = data;
        const jamData = await getJamSessionFromFirestore(jam_id);
        if (jamData && jamData.host_id === socket.userId) { // Ensure only host can trigger
            io.to(jam_id).emit('seek_sync', { jam_id, current_time });
            // Update Firestore with the new seek time
            await updateJamSessionInFirestore(jam_id, { current_time });
            activeJamSessions[jam_id].current_time = current_time;
            console.log(`Host ${socket.userId} seeked in jam ${jam_id} to ${current_time}s`);
        } else {
            socket.emit('error_message', { message: "Only the host can seek." });
        }
    });

    socket.on('leave_jam', async (data) => {
        if (!db || !auth) {
            socket.emit('error_message', { message: "Server Firebase not initialized. Cannot leave jam." });
            return;
        }
        const { jam_id, user_id, nickname } = data;
        if (!jam_id || !user_id) return;

        try {
            const jamDoc = await getJamSessionFromFirestore(jam_id);
            if (!jamDoc) {
                console.warn(`Attempted to leave non-existent or inactive jam: ${jam_id}`);
                return;
            }

            let updatedParticipants = jamDoc.participants.filter(p => p.user_id !== user_id);
            let disconnectMessage = `${nickname} has left the session.`;
            let newHostSocketId = null;
            let updatedIsActive = jamDoc.is_active;

            if (jamDoc.host_id === user_id) {
                // If the host is leaving, the session should end, or a new host needs to be assigned.
                // For simplicity, let's end the session if the host leaves.
                updatedIsActive = false;
                disconnectMessage = `The host (${nickname}) has ended the jam session.`;
                console.log(`Host ${nickname} (${user_id}) ended jam ${jam_id}.`);
            } else {
                // Disconnected user was a regular participant
                console.log(`${nickname} (${socket.id}) disconnected from jam ${jam_id}.`);
            }

            await updateJamSessionInFirestore(jam_id, {
                participants: updatedParticipants,
                host_sid: newHostSocketId, // Update host_sid if changed
                is_active: updatedIsActive
            });

            if (updatedIsActive) {
                // Only broadcast if session is still active
                io.to(jam_id).emit('update_participants', { jam_id: jam_id, participants: updatedParticipants });
            } else {
                // If session ended, inform all
                io.to(jam_id).emit('session_ended', { message: disconnectMessage });
            }
        } catch (error) {
            console.error("Error handling leave_jam:", error);
            socket.emit('error_message', { message: `Failed to leave jam: ${error.message}` });
        }
    });

    socket.on('disconnect', async (reason) => {
        console.log('User disconnected:', socket.id, 'Reason:', reason);
        // Find if this socket was part of any active jam session
        const jamId = socket.jamId; // Assuming jamId is stored on the socket object
        const userId = socket.userId;
        const nickname = socket.nickname;

        if (jamId && userId) {
            const jamDoc = await getJamSessionFromFirestore(jamId);
            if (jamDoc) {
                let updatedParticipants = jamDoc.participants.filter(p => p.user_id !== userId);
                let disconnectMessage = `${nickname || 'A participant'} has disconnected.`;
                let newHostSocketId = jamDoc.host_sid;
                let updatedIsActive = jamDoc.is_active;

                if (jamDoc.host_id === userId) {
                    // If the host disconnected, the session ends
                    updatedIsActive = false;
                    disconnectMessage = `The host (${nickname || 'Unknown Host'}) has disconnected, ending the jam session.`;
                    console.log(`Host ${nickname} (${socket.id}) disconnected from jam ${jamId}. Session ended.`);
                } else {
                    // Disconnected user was a regular participant
                    console.log(`${nickname || 'A participant'} (${socket.id}) disconnected from jam ${jamId}.`);
                }

                await updateJamSessionInFirestore(jamId, {
                    participants: updatedParticipants,
                    host_sid: newHostSocketId,
                    is_active: updatedIsActive
                });

                if (updatedIsActive) {
                    io.to(jamId).emit('update_participants', { jam_id: jamId, participants: updatedParticipants });
                } else {
                    io.to(jamId).emit('session_ended', { message: disconnectMessage });
                }
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
    console.log("Remember to set VERCEL_URL in your Vercel project settings for shareable links to work correctly in production.");
});
*/
