function onGmailMessage(e) {
  var messageId = e.gmail.messageId;

  try {
    var result = analyzeEmail(messageId);
    return [buildResultCard(result)];
  } catch (err) {
    return [buildErrorCard(err.message)];
  }
}

function onHomepage(e) {
  return [buildHomepageCard()];
}
