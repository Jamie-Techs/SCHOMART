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

// Function to request permission and get the token
export async function requestNotificationPermission() {
    try {
        const permission = await Notification.requestPermission();
        if (permission === 'granted') {
            const currentToken = await getToken(messaging, { vapidKey: VAPID_KEY });
            if (currentToken) {
                console.log("FCM Token:", currentToken);
                // TODO: Send this token to your backend to save it in Firestore
                return currentToken;
            } else {
                console.log("No registration token available.");
            }
        } else {
            console.log("Permission denied.");
        }
    } catch (err) {
        console.error("Error getting token:", err);
    }
    return null;
}

// Handle incoming messages while the app is in the foreground
onMessage(messaging, (payload) => {
    console.log("Foreground message received:", payload);
    new Notification(payload.notification.title, {
        body: payload.notification.body
    });
});
