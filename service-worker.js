const CACHE_NAME = 'schomart-cache-v1';
const urlsToCache = [
  '/',
  '/home',
  '/admin_settings.html',
  '/add_category.html',
  '/admin.html',
  '/admin_get_adverts.html',
  '/admin_get_online.html',
  '/admin_get_reports_adverts.html',
  '/admin_review.html',
  '/advert_detail.html',
  '/bank_transfer_instructions.html',
  '/base.html',
  '/cgpa_calculator.html',
  '/change_email.html',
  '/change_language.html',
  '/change_password.html',
  '/change_username.html',
  '/chat_interface.html',
  '/choose_advert_option.html',
  '/confirm_bank_transfer.html',
  '/create_post.html',
  '/create_post_gist.html',
  '/create_post_news.html',
  '/customer_care_chat.html',
  '/delete_account.html',
  '/disable_chats.html',
  '/disable_feedback_form.html',
  '/edit_advert_publication.html',
  '/faq.html',
  '/followers.html',
  '/full_post_detail.html',
  '/get_materials.html',
  '/header.html',
  '/identity_verification_wait.html',
  '/index.html',
  '/leaderboard.html',
  '/list_adverts.html',
  '/login.html',
  '/logout.html',
  '/manage_notification.html',
  '/messages.html',
  '/notification_management.html',
  '/notification_settings.html',
  '/notifications.html',
  '/payment.html',
  '/personal_details.html',
  '/post_details.html',
  '/post_for_pdf.html',
  '/post_material.html',
  '/profile.html',
  '/progress_chart.html',
  '/public_leaderboard.html',
  '/reported_advert_detail_admin.html',
  '/reported_adverts_admin.html',
  '/saved_adverts.html',
  '/school.html',
  '/school_content.html',
  '/school_gist.html',
  '/school_news.html',
  '/search.html',
  '/sell.html',
  '/sell_public_view.html',
  '/settings.html',
  '/signup.html',
  '/single_post.html',
  '/study_hub.html',
  '/subscribe.html',
  '/upload_study_material.html',
  '/user_profile.html',
  '/verify_email.html',
  '/verify_referral.html',
  '/view_image.html',
  '/view_post.html',
  '/visitors_profile_view.html',
  '/static/css/main.css',
  '/static/js/app.js',
  '/static/images/default_profile.png',
  '/static/images/schomart_logo.png',
  '/static/images/icon-512x512.png',
  'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.3/css/all.min.css'
];

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => {
        console.log('Opened cache');
        return cache.addAll(urlsToCache);
      })
  );
});

self.addEventListener('fetch', event => {
  event.respondWith(
    caches.match(event.request)
      .then(response => {
        if (response) {
          return response;
        }
        return fetch(event.request);
      })
  );
});
