// content.js

const currentUrl = window.location.href;

// Send the URL to background.js for phishing detection
chrome.runtime.sendMessage(
  { type: "checkPhishing", url: currentUrl },
  (response) => {
    if (response && response.isPhishing) {
      alert("⚠️ WARNING: This website may be a phishing site!");
    }
  }
);
