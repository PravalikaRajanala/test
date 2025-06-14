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
        db = admin.firestore();
        auth = admin.auth();
        console.log("Firebase Admin SDK initialized SUCCESSFULLY. Firestore and Auth instances available.");
    } catch (e) {
        console.error("CRITICAL ERROR: Error parsing FIREBASE_ADMIN_CREDENTIALS_JSON or initializing Firebase Admin SDK:", e.message, e.stack);
        console.error("Please ensure the FIREBASE_ADMIN_CREDENTIALS_JSON environment variable contains a single-line, valid JSON string for your Firebase service account.");
    }
}

// --- Express App Setup ---
const app = express();
// Create an HTTP server instance for Socket.IO to attach to.
// Vercel will wrap the 'app' export and handle the actual listening.
const server = http.createServer(app);

// Configure CORS for Express
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST'],
    credentials: true,
}));

// Use Express's built-in body parser for JSON requests
app.use(express.json());

// --- Socket.IO Setup ---
// Attach Socket.IO to the http server
const io = new Server(server, {
    cors: {
        origin: '*',
        methods: ['GET', 'POST'],
        credentials: true,
    },
    pingTimeout: 60000,
});

// --- In-Memory State for Jam Sessions (Server-Side - ephemeral on serverless) ---
const activeJamSessions = {};

// --- Serve Static Files ---
// This middleware serves all static files (index.html, manifest.json, etc.)
// from the root directory of your project.
app.use(express.static(path.join(__dirname)));

// Basic root route for testing if Express is working
app.get('/', (req, res) => {
    // If express.static already served index.html, this route won't be hit for /.
    // This serves as a fallback or explicit handler if needed for the root path.
    res.sendFile(path.join(__dirname, 'index.html'), (err) => {
        if (err) {
            console.error("Error serving index.html from root route:", err);
            // Fallback for when index.html might not be directly found by sendFile
            res.status(404).send("<html><body><h1>404 Not Found</h1><p>The main page could not be loaded.</p></body></html>");
        }
    });
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

app.post('/logout', (req, res) => {
    console.log("Logout endpoint hit. Clearing session cookie.");
    res.status(200).json({ message: "Logged out successfully (server-side acknowledged)." });
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
        const { jam_name, nickname } = data;
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
            host_user_id: userId,
            participants: { [socket.id]: nickname },
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
            await updateJamSessionInFirestore(jamId, newJam);
            socket.join(jamId);
            activeJamSessions[jamId] = { host_sid: socket.id, participants: { [socket.id]: nickname } };
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
        const { jam_id, nickname } = data;
        const jamDocData = await getJamSessionFromFirestore(jam_id);

        if (!jamDocData || !jamDocData.is_active) {
            socket.emit('join_failed', { message: `Jam session ${jam_id} not found or is inactive.` });
            return;
        }
        const updatedParticipants = { ...jamDocData.participants, [socket.id]: nickname };
        await updateJamSessionInFirestore(jam_id, { participants: updatedParticipants });

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
        const jamDocData = await getJamSessionFromFirestore(jam_id);

        if (!jamDocData || jamDocData.host_sid !== socket.id || !jamDocData.is_active) {
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
            await updateJamSessionInFirestore(jam_id, {
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
        const jamDocData = await getJamSessionFromFirestore(jam_id);

        if (!jamDocData || jamDocData.host_sid !== socket.id || !jamDocData.is_active) {
            console.warn(`Attempted to add song from non-host or inactive session: ${socket.id} for jam ${jam_id}`);
            return;
        }
        const updatedPlaylist = [...(jamDocData.playlist || []), song];
        try {
            await updateJamSessionInFirestore(jam_id, { playlist: updatedPlaylist });
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
        const jamDocData = await getJamSessionFromFirestore(jam_id);

        if (!jamDocData || jamDocData.host_sid !== socket.id || !jamDocData.is_active) {
            console.warn(`Attempted to remove song from non-host or inactive session: ${socket.id} for jam ${jam_id}`);
            return;
        }
        const originalPlaylist = jamDocData.playlist || [];
        const updatedPlaylist = originalPlaylist.filter(song => song.id !== song_id);

        if (updatedPlaylist.length === originalPlaylist.length) {
            console.warn(`Song with ID ${song_id} not found in jam ${jam_id}'s playlist.`);
            return;
        }
        try {
            await updateJamSessionInFirestore(jam_id, { playlist: updatedPlaylist });
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
        const jamDocData = await getJamSessionFromFirestore(jam_id);

        if (!jamDocData || !jamDocData.is_active) {
            console.warn(`Attempted to leave inactive or non-existent jam: ${jam_id}`);
            return;
        }
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
                await updateJamSessionInFirestore(jam_id, {
                    host_sid: newHostSocketId,
                    participants: updatedParticipants
                });
                io.to(jam_id).emit('update_participants', { jam_id: jam_id, participants: updatedParticipants });
                io.to(jam_id).emit('session_ended', { message: `Host changed for Jam Session "${jamDocData.name}".` });
            } else {
                updatedIsActive = false;
                await updateJamSessionInFirestore(jam_id, { is_active: false, participants: updatedParticipants });
                io.to(jam_id).emit('session_ended', { message: `Jam Session "${jamDocData.name}" has ended as host left.` });
                delete activeJamSessions[jam_id];
            }
        } else {
            await updateJamSessionInFirestore(jam_id, { participants: updatedParticipants });
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
        const jamSessionDocs = await db.collection('jam_sessions').where('is_active', '==', true).get();
        for (const docSnapshot of jamSessionDocs.docs) {
            const jamId = docSnapshot.id;
            const jamDocData = docSnapshot.data();

            if (jamDocData.participants && jamDocData.participants[socket.id]) {
                const updatedParticipants = { ...jamDocData.participants };
                const leftNickname = updatedParticipants[socket.id];
                delete updatedParticipants[socket.id];

                let newHostSocketId = jamDocData.host_sid;
                let updatedIsActive = jamDocData.is_active;
                let disconnectMessage = `${leftNickname} has left the session.`;

                if (jamDocData.host_sid === socket.id) {
                    if (Object.keys(updatedParticipants).length > 0) {
                        newHostSocketId = Object.keys(updatedParticipants)[0];
                        console.log(`Host ${leftNickname} (${socket.id}) disconnected from jam ${jamId}. New host: ${newHostSocketId}`);
                        io.to(jamId).emit('session_ended', { message: `Host changed for Jam Session "${jamDocData.name}".` });
                    } else {
                        updatedIsActive = false;
                        console.log(`Host ${leftNickname} (${socket.id}) disconnected. Jam ${jamId} ended.`);
                        disconnectMessage = `Jam Session "${jamDocData.name}" has ended as host disconnected.`;
                        delete activeJamSessions[jamId];
                    }
                } else {
                    console.log(`${leftNickname} (${socket.id}) disconnected from jam ${jamId}.`);
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
    console.log("For Vercel deployment, remember to set FIREBASE_ADMIN_CREDENTIALS_JSON and VERCEL_URL.");
});
*/
