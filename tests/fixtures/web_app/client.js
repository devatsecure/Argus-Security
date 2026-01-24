/**
 * Client-side JavaScript for web app
 * TRUE POSITIVE XSS vulnerabilities - this runs in browser
 */

// XSS vulnerability - innerHTML with user input (TRUE POSITIVE)
function displayUserMessage(message) {
  const output = document.getElementById('output');
  // VULNERABLE: innerHTML with unsanitized user input
  output.innerHTML = message;
}

// XSS vulnerability - document.write (TRUE POSITIVE)
function renderUserContent(content) {
  // VULNERABLE: document.write with user input
  document.write(`<div class="user-data">${content}</div>`);
}

// XSS vulnerability - DOM manipulation (TRUE POSITIVE)
function updateUserProfile() {
  const params = new URLSearchParams(window.location.search);
  const userName = params.get('name');

  // VULNERABLE: innerHTML with URL parameter
  const profile = document.getElementById('user-content');
  profile.innerHTML = `<h2>Welcome, ${userName}!</h2>`;
}

// Safe alternative - textContent (NOT XSS vulnerable)
function displaySafeMessage(message) {
  const output = document.getElementById('output');
  // SAFE: textContent does not parse HTML
  output.textContent = message;
}

// Event listener
document.addEventListener('DOMContentLoaded', () => {
  updateUserProfile();
});
