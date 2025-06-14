// app.js - Node.js Backend for TuneJam
// This server handles Socket.IO real-time communication for jam sessions,
// serves static files, and provides API endpoints for song search and logout.

// Load environment variables from .env file in development.
// On Vercel, environment variables are automatically available.
require('dotenv').config();

// --- Module Imports ---
const express = require('express');
const http = require('http'); // Required for Socket.IO (but server.listen() removed for Vercel export)
const { Server } = require('socket.io');
const cors = require('cors'); // For handling Cross-Origin Resource Sharing
const path = require('path'); // For path manipulation
const fs = require('fs'); // For reading file system (e.g., manifest.json)
const admin = require('firebase-admin'); // Firebase Admin SDK

// --- Firebase Admin SDK Initialization ---
// Initialize Firebase Admin SDK using credentials from environment variable.
// This is crucial for secure server-side interactions with Firestore.
// The FIREBASE_ADMIN_CREDENTIALS_JSON should be the entire JSON content
// of your service account key file, stored as an environment variable.
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
// NOTE: For Vercel, we create the HTTP server for Socket.IO but don't call .listen()
// Vercel wraps the exported Express app and handles the listening.
const server = http.createServer(app); 

// Configure CORS for Express (for API endpoints if accessed directly)
app.use(cors({
    origin: '*', // Allow all origins for development and Vercel deployments. Be more restrictive in production if needed.
    methods: ['GET', 'POST'],
    credentials: true, // Allow cookies to be sent
}));

// Use Express's built-in body parser for JSON requests
app.use(express.json());

// --- Socket.IO Setup ---
// Configure CORS for Socket.IO specifically. This is important for client-server communication.
// Attach Socket.IO to the http server
const io = new Server(server, {
    cors: {
        origin: '*', // Allow all origins for Socket.IO connections
        methods: ['GET', 'POST'],
        credentials: true,
    },
    pingTimeout: 60000, 
});

// --- In-Memory State for Jam Sessions (Server-Side - ephemeral on serverless) ---
// Note: On Vercel, these will reset with each cold start. Firestore is the primary source of truth.
const activeJamSessions = {}; 

// --- Serve Static Files ---
// This line is crucial for serving all your frontend assets (index.html, manifest.json, css, js, icons etc.)
// from the root directory. It should be placed BEFORE any specific API routes or the root route,
// so that Express serves static files first if they match.
app.use(express.static(path.join(__dirname)));

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

// Endpoint for searching hosted MP3s
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

// Basic logout endpoint. In a real Firebase Auth scenario, client-side signOut
// is primary. This server-side part might be for clearing server-set cookies.
app.post('/logout', (req, res) => {
    console.log("Logout endpoint hit. Clearing session cookie.");
    res.status(200).json({ message: "Logged out successfully (server-side acknowledged)." });
});

// --- Socket.IO Event Handlers ---

// Utility to generate a short unique ID for jam sessions
function generateShortUniqueId() {
    return Math.random().toString(36).substring(2, 8).toUpperCase(); // 6 characters
}

// Helper to get jam session data from Firestore
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

// Helper to update jam session data in Firestore
async function updateJamSessionInFirestore(jamId, data) {
    if (!db) {
        console.error("Firestore DB not initialized. Cannot update jam session data.");
        return;
    }
    try {
        const docRef = db.collection('jam_sessions').doc(jamId);
        await docRef.set(data, { merge: true }); // Merge updates existing fields
        console.log(`Jam session ${jamId} updated in Firestore.`);
    } catch (error) {
        console.error(`Error updating jam session ${jamId} in Firestore:`, error);
    }
}

// Map Socket ID to User ID (useful for tracking participants in a jam session)
const socketIdToUserId = {};

io.on('connection', (socket) => {
    console.log(`A user connected: ${socket.id}`);

    // Get userId from the query parameter if available (set by client-side JS)
    const userId = socket.handshake.query.userId;
    if (userId) {
        socketIdToUserId[socket.id] = userId;
        console.log(`Socket ${socket.id} mapped to User ID: ${userId}`);
    } else {
        console.warn(`Socket ${socket.id} connected without a User ID.`);
    }

    // Handle session creation
    socket.on('create_session', async (data) => {
        if (!db) {
            socket.emit('join_failed', { message: "Server is not configured for Firebase. Cannot create jam session." });
            return;
        }

        const { jam_name, nickname } = data;
        let jamId = generateShortUniqueId();

        // Ensure generated ID is unique (unlikely to clash in short IDs, but good practice)
        let jamDoc = await getJamSessionFromFirestore(jamId);
        while (jamDoc && jamDoc.is_active) {
            jamId = generateShortUniqueId();
            jamDoc = await getJamSessionFromFirestore(jamId);
        }

        const newJam = {
            id: jamId,
            name: jam_name || `Jam Session ${jamId}`,
            host_sid: socket.id, // Store host's socket ID
            host_user_id: userId, // Store host's Firebase User ID
            participants: { [socket.id]: nickname }, // Store participants by socket ID
            playlist: [],
            playback_state: {
                current_track_index: 0,
                current_playback_time: 0,
                is_playing: false,
                timestamp: admin.firestore.FieldValue.serverTimestamp() // Firestore timestamp
            },
            is_active: true, // Mark session as active
            created_at: admin.firestore.FieldValue.serverTimestamp()
        };

        try {
            await updateJamSessionInFirestore(jamId, newJam);
            socket.join(jamId); // Host joins the Socket.IO room
            activeJamSessions[jamId] = { host_sid: socket.id, participants: { [socket.id]: nickname } }; // Update in-memory for quick lookup

            // VERCEL_URL is provided by Vercel for production deployments. For local, use localhost.
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

    // Handle joining an existing session
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

        // Add new participant to the session
        const updatedParticipants = { ...jamDocData.participants };
        await updateJamSessionInFirestore(jam_id, { participants: updatedParticipants });

        socket.join(jam_id); // User joins the Socket.IO room
        // Update in-memory if this jam_id is tracked, else create entry (less critical for non-hosts)
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
            last_synced_at: jamDocData.playback_state.timestamp ? jamDocData.playback_state.timestamp.seconds : 0, // Convert Firestore timestamp to seconds
            participants: updatedParticipants,
            nickname_used: nickname
        });

        // Inform all other participants in the room about the new participant
        io.to(jam_id).emit('update_participants', { jam_id: jam_id, participants: updatedParticipants });
        console.log(`${nickname} (${socket.id}) joined jam session ${jam_id}.`);
    });

    // Handle playback state synchronization from host
    socket.on('sync_playback_state', async (data) => {
        if (!db) {
            console.error("Firestore DB not initialized. Cannot sync playback state.");
            return;
        }

        const { jam_id, current_track_index, current_playback_time, is_playing, playlist } = data;
        const jamDocData = await getJamSessionFromFirestore(jam_id);

        if (!jamDocData || jamDocData.host_sid !== socket.id || !jamDocData.is_active) {
            console.warn(`Attempted sync from non-host or inactive session: ${socket.id} for jam ${jam_id}`);
            return; // Only host can sync
        }

        const playbackState = {
            current_track_index: current_track_index,
            current_playback_time: current_playback_time,
            is_playing: is_playing,
            timestamp: admin.firestore.FieldValue.serverTimestamp()
        };

        try {
            await updateJamSessionInFirestore(jam_id, {
                playlist: playlist, // Host's playlist is the source of truth
                playback_state: playbackState
            });
            console.log(`Jam ${jam_id} playback state synced by host ${socket.id}.`);
        } catch (error) {
            console.error(`Error syncing playback state for jam ${jam_id}:`, error);
        }
    });

    // Handle adding a song to the jam session playlist (host only)
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

    // Handle removing a song from the jam session playlist (host only)
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
            return; // Song not found, no update needed
        }

        try {
            await updateJamSessionInFirestore(jam_id, { playlist: updatedPlaylist });
            console.log(`Song with ID ${song_id} removed from jam ${jam_id} by host ${socket.id}.`);
        } catch (error) {
            console.error(`Error removing song from jam ${jam_id}:`, error);
        }
    });

    // Handle leaving a session
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

        // Remove participant from the session
        const updatedParticipants = { ...jamDocData.participants };
        const leftNickname = updatedParticipants[socket.id];
        delete updatedParticipants[socket.id];

        socket.leave(jam_id); // User leaves the Socket.IO room

        let updatedIsActive = jamDocData.is_active;

        if (jamDocData.host_sid === socket.id) {
            // Host is leaving
            console.log(`Host ${leftNickname} (${socket.id}) is leaving jam ${jam_id}.`);
            if (Object.keys(updatedParticipants).length > 0) {
                // If there are other participants, assign a new host randomly (first one in the list for simplicity)
                const newHostSocketId = Object.keys(updatedParticipants)[0];
                console.log(`Assigning new host for jam ${jamId}: ${newHostSocketId}`);
                await updateJamSessionInFirestore(jam_id, {
                    host_sid: newHostSocketId,
                    participants: updatedParticipants
                });
                // Notify remaining participants about the host change
                io.to(jam_id).emit('update_participants', { jam_id: jam_id, participants: updatedParticipants });
                io.to(jam_id).emit('session_ended', { message: `Host changed for Jam Session "${jamDocData.name}".` }); // Temporary message
            } else {
                // No other participants, end the session
                updatedIsActive = false;
                await updateJamSessionInFirestore(jam_id, { is_active: false, participants: updatedParticipants });
                io.to(jam_id).emit('session_ended', { message: `Jam Session "${jamDocData.name}" has ended as host left.` });
                delete activeJamSessions[jam_id]; // Remove from in-memory if host left and no one left
            }
        } else {
            // Regular participant is leaving
            await updateJamSessionInFirestore(jam_id, { participants: updatedParticipants });
            io.to(jam_id).emit('update_participants', { jam_id: jam_id, participants: updatedParticipants }); // Inform remaining participants
            console.log(`${leftNickname} (${socket.id}) left jam session ${jam_id}.`);
        }
    });

    // Handle client disconnect
    socket.on('disconnect', async () => {
        console.log(`User disconnected: ${socket.id}`);
        // Remove mapping
        delete socketIdToUserId[socket.id];

        // Only proceed if db is initialized to avoid errors
        if (!db) {
            console.warn("Firestore DB not initialized. Skipping disconnect logic for jam sessions.");
            return;
        }

        // Check if the disconnected user was part of any active jam session
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
                    // Disconnected user was the host
                    if (Object.keys(updatedParticipants).length > 0) {
                        // Assign a new host if others are present
                        newHostSocketId = Object.keys(updatedParticipants)[0];
                        console.log(`Host ${leftNickname} (${socket.id}) disconnected from jam ${jamId}. New host: ${newHostSocketId}`);
                        // Notify remaining participants about the host change
                        io.to(jamId).emit('session_ended', { message: `Host changed for Jam Session "${jamDocData.name}".` }); // Temporary message for all clients to re-sync
                    } else {
                        // No other participants, end the session
                        updatedIsActive = false;
                        console.log(`Host ${leftNickname} (${socket.id}) disconnected. Jam ${jamId} ended.`);
                        disconnectMessage = `Jam Session "${jamDocData.name}" has ended as host disconnected.`;
                        delete activeJamSessions[jamId]; // Remove from in-memory
                    }
                } else {
                    // Disconnected user was a regular participant
                    console.log(`${leftNickname} (${socket.id}) disconnected from jam ${jamId}.`);
                }

                await updateJamSessionInFirestore(jamId, {
                    participants: updatedParticipants,
                    host_sid: newHostSocketId, // Update host_sid if changed
                    is_active: updatedIsActive
                });

                if (updatedIsActive) {
                    // Only broadcast if session is still active
                    io.to(jamId).emit('update_participants', { jam_id: jamId, participants: updatedParticipants });
                } else {
                    // If session ended, inform all
                    io.to(jamId).emit('session_ended', { message: disconnectMessage });
                }
            }
        }
    });
});


// --- Error Handling (for Express) ---
// This is a catch-all for unhandled Express errors.
app.use((err, req, res, next) => {
    console.error("Express error caught:", err.stack);
    res.status(500).send('An internal server error occurred.');
});

// IMPORTANT for Vercel: Export the Express app
// Vercel wraps this exported app and handles the server listening.
module.exports = app;

// The app.listen() call below is ONLY for local development.
// It will be ignored by Vercel's serverless environment.
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Server running LOCALLLY on port ${PORT}`);
    console.log(`Access the application locally at: http://localhost:${PORT}`);
    console.log("For Vercel deployment, remember to set FIREBASE_ADMIN_CREDENTIALS_JSON and VERCEL_URL.");
});
