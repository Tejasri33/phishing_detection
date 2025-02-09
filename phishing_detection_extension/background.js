// background.js

chrome.runtime.onInstalled.addListener(() => {
  console.log("Phishing Detector Extension Installed!");
});

// Listen for events from content.js
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === "checkPhishing") {
    fetch("http://localhost:5000/check", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ url: request.url })
    })
      .then(response => response.json())
      .then(data => {
        sendResponse({ isPhishing: data.isPhishing });
      })
      .catch(error => console.error("Error:", error));

    return true;  // Keep the message channel open for async response
  }
});
