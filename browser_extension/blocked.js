const params = new URLSearchParams(location.search);
const blockedUrl = params.get("url") || "";
const reason = params.get("reason") || "";

const reasonMap = {
  "ads": "Tracking Attempt",
  "malware": "Malware Detection",
  "scam": "Scam or Phishing Attempt"
};

const displayReason = reasonMap[reason] || "Malicious Activity";
const eyebrow = document.querySelector(".eyebrow");
if (eyebrow) {
  eyebrow.textContent = `Website blocked due to ${displayReason}`;
}

document.getElementById("blockedUrl").textContent = blockedUrl;
document.getElementById("backButton").addEventListener("click", () => {
  history.length > 1 ? history.back() : location.assign("about:blank");
});

document.getElementById("continueButton").addEventListener("click", async () => {
  if (!blockedUrl) {
    return;
  }
  await chrome.runtime.sendMessage({
    type: "continueToSite",
    url: blockedUrl
  });
  location.assign(blockedUrl);
});
