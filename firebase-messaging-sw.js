// firebase-messaging-sw.js

// Import and initialize the Firebase SDK for the service worker
importScripts("https://www.gstatic.com/firebasejs/9.23.0/firebase-app.js");
importScripts("https://www.gstatic.com/firebasejs/9.23.0/firebase-messaging.js");

// Your Firebase configuration
// REPLACE WITH YOUR ACTUAL CONFIG
const firebaseConfig = {
    apiKey: "AIzaSyBEJOF1jZAIIV8_i6xvUHlSKeqOlcQ-Sgo",
    authDomain: "schomart-7a743.firebaseapp.com",
    projectId: "schomart-7a743",
    storageBucket: "schomart-7a743.firebasestorage.app",
    messagingSenderId: "20119186662",
    appId: "1:20119186662:web:da1755b55dacde4fa6df27",
    measurementId: "G-9QGL3XHSC7"
};

const app = firebase.initializeApp(firebaseConfig);
const messaging = firebase.messaging();

// Optional: Handle incoming background messages here
// This function is triggered when a message arrives and the app is not in the foreground.
messaging.onBackgroundMessage((payload) => {
    console.log('[firebase-messaging-sw.js] Received background message ', payload);
    
    // Customize notification here
    const notificationTitle = payload.notification.title;
    const notificationOptions = {
        body: payload.notification.body,
        icon: '/favicon.ico' // Ensure you have a valid icon path
    };

    self.registration.showNotification(notificationTitle, notificationOptions);
});
