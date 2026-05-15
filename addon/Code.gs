function onGmailMessage(e) {
  var messageId = e.gmail.messageId;

  try {
    var result = analyzeEmail(messageId);

    var b = result.breakdown    || {};
    var s = result.signals      || {};
    var c = result.calculation  || {};

    Logger.log("═══════════════════════════════════════");
    Logger.log("  UPDOG ANALYSIS REPORT");
    Logger.log("═══════════════════════════════════════");
    Logger.log("  Message ID : " + messageId);
    Logger.log("  Score      : " + result.score + " / 100");
    Logger.log("  Verdict    : " + result.verdict.toUpperCase());
    Logger.log("───────────────────────────────────────");
    Logger.log("  ANALYZER SCORES");
    Logger.log("  Headers     : " + pct(b.header));
    Logger.log("  Sender      : " + pct(b.sender));
    Logger.log("  URLs        : " + pct(b.url));
    Logger.log("  Content     : " + pct(b.content));
    Logger.log("  Attachments : " + pct(b.attachment));
    Logger.log("───────────────────────────────────────");
    Logger.log("  HEADER SIGNALS");
    logSignals(s.header);
    Logger.log("  SENDER SIGNALS");
    logSignals(s.sender);
    Logger.log("  URL SIGNALS");
    logSignals(s.url);
    Logger.log("  CONTENT SIGNALS");
    logSignals(s.content);
    Logger.log("  ATTACHMENT SIGNALS");
    logSignals(s.attachment);
    Logger.log("───────────────────────────────────────");
    Logger.log("  SCORE CALCULATION");
    var contrib = c.contributions || {};
    Object.keys(contrib).forEach(function(k) {
      Logger.log("    " + k + ": +" + contrib[k] + " pts");
    });
    Logger.log("    ──────────────────────────");
    Logger.log("    weighted total : " + c.weighted_score + " / 100");
    if (c.floor_applied) {
      Logger.log("    floor applied  : " + c.floor_reason);
    }
    Logger.log("    final score    : " + c.final_score + " / 100");
    Logger.log("───────────────────────────────────────");
    Logger.log("  FINDINGS");
    (result.bullets || []).forEach(function(b) { Logger.log("  " + b); });
    Logger.log("═══════════════════════════════════════");

    return [buildResultCard(result)];
  } catch (err) {
    return [buildErrorCard(err.message)];
  }
}

function onHomepage(e) {
  return [buildHomepageCard()];
}

function pct(val) {
  if (val === undefined || val === null) return "N/A";
  return Math.round(val * 100) + "%";
}

function logSignals(obj) {
  if (!obj) { Logger.log("  (none)"); return; }
  Object.keys(obj).forEach(function(key) {
    var val = obj[key];
    if (val === null || val === undefined) return;
    Logger.log("    " + key + ": " + val);
  });
}
