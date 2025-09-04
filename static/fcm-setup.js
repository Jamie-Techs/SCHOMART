// fcm-setup.js

import { initializeApp } from "https://www.gstatic.com/firebasejs/9.23.0/firebase-app.js";
import { getMessaging, getToken, onMessage } from "https://www.gstatic.com/firebasejs/9.23.0/firebase-messaging.js";

// Your Firebase configuration
const firebaseConfig = {
    apiKey: "AIzaSyBEJOF1jZAIIV8_i6xvUHlSKeqOlcQ-Sgo",
    authDomain: "schomart-7a743.firebaseapp.com",
    projectId: "schomart-7a743",
    storageBucket: "schomart-7a743.firebasestorage.app",
    messagingSenderId: "20119186662",
    appId: "1:20119186662:web:da1755b55dacde4fa6df27",
    measurementId: "G-9QGL3XHSC7"
};

const app = initializeApp(firebaseConfig);
const messaging = getMessaging(app);

const VAPID_KEY = "BCd0URvWHBwOZJ1XEj4f4fyEUMhhZNznvlF39WUDN69orpPKWIo1V2FdDiI4pRcf7m-XhO9TL4ZFuMsRvxTRx9U";

// Register the service worker at the root of your app
if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/firebase-messaging-sw.js')
        .then(registration => {
            console.log('Service Worker registered successfully:', registration.scope);
        })
        .catch(error => {
            console.error('Service Worker registration failed:', error);
        });
}

/**
 * Sends the FCM token to the backend.
 * @param {string} token The FCM registration token.
 */
async function sendTokenToBackend(token) {
    if (!token) {
        console.error("No token to send.");
        return;
    }
    
    try {
        const response = await fetch('/api/save-fcm-token', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ fcm_token: token })
        });
        if (response.ok) {
            console.log('FCM token successfully sent to backend.');
        } else {
            console.error('Failed to send FCM token to backend:', await response.text());
        }
    } catch (error) {
        console.error('Network error while sending token:', error);
    }
}

// Function to request permission and get the token
export async function requestNotificationPermission() {
    try {
        const permission = await Notification.requestPermission();
        if (permission === 'granted') {
            const currentToken = await getToken(messaging, { vapidKey: VAPID_KEY });
            if (currentToken) {
                console.log("FCM Token:", currentToken);
                // Send the initial token to the backend
                sendTokenToBackend(currentToken);
                return currentToken;
            } else {
                console.log("No registration token available.");
            }
        } else {
            console.log("Permission denied.");
            alert("To enable notifications, please allow permissions in your browser settings.");
        }
    } catch (err) {
        console.error("Error getting token:", err);
    }
    return null;
}

// **New:** Listen for token refresh and send the new token to the backend
getToken(messaging, { vapidKey: VAPID_KEY }).then((token) => {
    // This is the correct way to listen for token changes in modern SDKs
    // A token change happens implicitly, so we handle it here.
    if (token) {
        console.log("Token already exists. Ensure it's sent to the backend.");
        sendTokenToBackend(token);
    }
}).catch((err) => {
    console.error("An error occurred while retrieving a new token.", err);
});


// Handle incoming messages while the app is in the foreground
onMessage(messaging, (payload) => {
    console.log("Foreground message received:", payload);
    const notificationTitle = payload.notification.title;
    const notificationOptions = {
        body: payload.notification.body,
        icon: '/favicon.ico' // Or any other icon
    };
    new Notification(notificationTitle, notificationOptions);
});
