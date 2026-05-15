var SCORE_CONFIG = {
  green:  { icon: "✅", label: "Safe",             color: "#2E7D32" },
  yellow: { icon: "⚠️",  label: "Suspicious",       color: "#F57F17" },
  orange: { icon: "🔶", label: "Likely Malicious",  color: "#E65100" },
  red:    { icon: "🚨", label: "Malicious",          color: "#B71C1C" },
};

var ANALYZER_LABELS = {
  header:     "Headers",
  sender:     "Sender",
  url:        "URLs",
  content:    "Content",
  attachment: "Attachments",
};

// ── Result card ──────────────────────────────────────────────────────────────

function buildResultCard(result) {
  var cfg     = SCORE_CONFIG[result.color] || SCORE_CONFIG.green;
  var score   = result.score;
  var bullets = result.bullets || [];

  var card = CardService.newCardBuilder()
    .setHeader(
      CardService.newCardHeader()
        .setTitle("UpDog")
        .setSubtitle("Phishing & Malware Scanner")
        .setImageUrl("https://raw.githubusercontent.com/TheMprs/Updog/main/addon/logo.png")
    );

  // ── Verdict section ──
  var verdictSection = CardService.newCardSection();

  verdictSection.addWidget(
    CardService.newDecoratedText()
      .setTopLabel("Risk Score")
      .setText(cfg.icon + "  <b>" + score + " / 100</b>  —  " + cfg.label)
      .setWrapText(false)
  );

  card.addSection(verdictSection);

  // ── Findings section ──
  if (score >= 31 && bullets.length > 0) {
    var findingsSection = CardService.newCardSection()
      .setHeader("Findings");

    bullets.forEach(function (bullet) {
      findingsSection.addWidget(
        CardService.newDecoratedText()
          .setText(bullet)
          .setWrapText(true)
      );
    });

    card.addSection(findingsSection);
  } else {
    var clearSection = CardService.newCardSection();
    clearSection.addWidget(
      CardService.newDecoratedText()
        .setText("✅  No suspicious signals detected.")
    );
    card.addSection(clearSection);
  }

  // ── Breach notification section ──
  var senderSignals = (result.signals && result.signals.sender) || {};
  if (senderSignals.domain_recent_breach) {
    var breachSection = CardService.newCardSection()
      .setHeader("⚠️ Known Data Breach");

    breachSection.addWidget(
      CardService.newDecoratedText()
        .setText(senderSignals.breach_info || "The sender's domain was involved in a known data breach.")
        .setWrapText(true)
    );

    breachSection.addWidget(
      CardService.newDecoratedText()
        .setText("Have you changed your password for this service since then?")
        .setWrapText(true)
    );

    var buttonSet = CardService.newButtonSet();

    buttonSet.addButton(
      CardService.newTextButton()
        .setText("Yes, I changed my password")
        .setOnClickAction(
          CardService.newAction().setFunctionName("onBreachSafe")
        )
    );

    var userEmail = "";
    try { userEmail = Session.getActiveUser().getEmail(); } catch (e) {}
    var hibpUrl = userEmail
      ? "https://haveibeenpwned.com/account/" + encodeURIComponent(userEmail)
      : "https://haveibeenpwned.com";

    buttonSet.addButton(
      CardService.newTextButton()
        .setText("No — check if I was exposed")
        .setOpenLink(
          CardService.newOpenLink()
            .setUrl(hibpUrl)
            .setOpenAs(CardService.OpenAs.FULL_SIZE)
        )
    );

    breachSection.addWidget(buttonSet);
    card.addSection(breachSection);
  }

  // ── Breakdown section (collapsible) ──
  if (result.breakdown) {
    var breakdownSection = CardService.newCardSection()
      .setHeader("Analyzer Breakdown")
      .setCollapsible(true)
      .setNumUncollapsibleWidgets(0);

    Object.keys(result.breakdown).forEach(function (key) {
      var rawScore = result.breakdown[key];
      var pct      = Math.round(rawScore * 100);
      var label    = ANALYZER_LABELS[key] || key;
      var bar      = scoreBar(pct);

      breakdownSection.addWidget(
        CardService.newDecoratedText()
          .setTopLabel(label)
          .setText(bar + "  " + pct + "%")
          .setWrapText(false)
      );
    });

    card.addSection(breakdownSection);
  }

  // ── Disclaimer section ──
  var disclaimerSection = CardService.newCardSection();
  disclaimerSection.addWidget(
    CardService.newDecoratedText()
      .setText("This score is an estimate and not a guarantee. When in doubt, avoid clicking links or downloading attachments — especially from senders you don't recognize.")
      .setWrapText(true)
  );
  card.addSection(disclaimerSection);

  return card.build();
}


// ── Error card ───────────────────────────────────────────────────────────────

function buildErrorCard(message) {
  return CardService.newCardBuilder()
    .setHeader(
      CardService.newCardHeader()
        .setTitle("UpDog")
        .setSubtitle("Analysis failed")
        .setImageUrl("https://raw.githubusercontent.com/TheMprs/Updog/main/addon/logo.png")
    )
    .addSection(
      CardService.newCardSection().addWidget(
        CardService.newDecoratedText()
          .setText("❌  " + message)
          .setWrapText(true)
      )
    )
    .build();
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function scoreBar(pct) {
  var filled = Math.round(pct / 10);
  var empty  = 10 - filled;
  return "█".repeat(filled) + "░".repeat(empty);
}

function onBreachSafe() {
  return CardService.newActionResponseBuilder()
    .setNotification(
      CardService.newNotification().setText("Good — your account is protected.")
    )
    .build();
}
