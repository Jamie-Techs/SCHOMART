// Import the necessary Firebase SDKs from the CDN
import { initializeApp } from 'https://www.gstatic.com/firebasejs/9.23.0/firebase-app.js';
import { getMessaging, onBackgroundMessage } from 'https://www.gstatic.com/firebasejs/9.23.0/firebase-messaging.js';

// Your web app's Firebase configuration
const firebaseConfig = {
    apiKey: "AIzaSyBEJOF1jZAIIV8_i6xvUHlSKeqOlcQ-Sgo",
    authDomain: "schomart-7a743.firebaseapp.com",
    projectId: "schomart-7a743",
    storageBucket: "schomart-7a743.firebasestorage.app",
    messagingSenderId: "20119186662",
    appId: "1:20119186662:web:da1755b55dacde4fa6df27",
    measurementId: "G-9QGL3XHSC7"
};

// Initialize the Firebase app in the service worker
const app = initializeApp(firebaseConfig);
const messaging = getMessaging(app);

// Handle messages when the app is in the background or terminated
onBackgroundMessage(messaging, (payload) => {
    console.log('[firebase-messaging-sw.js] Received background message ', payload);
    
    // Customize your notification based on the message payload
    const notificationTitle = payload.notification.title;
    const notificationOptions = {
        body: payload.notification.body,
        icon: '/firebase-logo.png' // A simple logo for the notification
    };
    
    self.registration.showNotification(notificationTitle, notificationOptions);
});
