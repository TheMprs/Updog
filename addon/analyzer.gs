var BACKEND_URL_KEY = "BACKEND_URL";
var AUTH_TOKEN_KEY  = "AUTH_TOKEN";

function analyzeEmail(messageId) {
  var message = GmailApp.getMessageById(messageId);
  var rawEmail = message.getRawContent(); 

  var props       = PropertiesService.getScriptProperties();
  var backendUrl  = props.getProperty(BACKEND_URL_KEY);
  var authToken   = props.getProperty(AUTH_TOKEN_KEY);

  if (!backendUrl) throw new Error("BACKEND_URL not set in Script Properties.");

  var options = {
    method:      "post",
    contentType: "application/json",
    payload:     JSON.stringify({ email: rawEmail }),
    headers:     { "Authorization": "Bearer " + (authToken || "") },
    muteHttpExceptions: true,
  };

  var response = UrlFetchApp.fetch(backendUrl + "/analyze", options);
  var code     = response.getResponseCode();

  if (code !== 200) {
    throw new Error("Backend returned " + code + ": " + response.getContentText());
  }

  return JSON.parse(response.getContentText());
}
