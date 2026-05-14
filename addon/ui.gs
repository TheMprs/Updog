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
        .setTitle("Email Shield")
        .setSubtitle("Phishing & Malware Scanner")
        .setImageUrl("https://www.gstatic.com/images/icons/material/system/2x/security_black_24dp.png")
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
  if (bullets.length > 0) {
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

  return card.build();
}

// ── Homepage card (no email open) ────────────────────────────────────────────

function buildHomepageCard() {
  return CardService.newCardBuilder()
    .setHeader(
      CardService.newCardHeader()
        .setTitle("Email Shield")
        .setSubtitle("Phishing & Malware Scanner")
        .setImageUrl("https://www.gstatic.com/images/icons/material/system/2x/security_black_24dp.png")
    )
    .addSection(
      CardService.newCardSection().addWidget(
        CardService.newDecoratedText()
          .setText("Open an email to scan it for phishing, malicious URLs, and spoofing.")
          .setWrapText(true)
      )
    )
    .build();
}

// ── Error card ───────────────────────────────────────────────────────────────

function buildErrorCard(message) {
  return CardService.newCardBuilder()
    .setHeader(
      CardService.newCardHeader()
        .setTitle("Email Shield")
        .setSubtitle("Analysis failed")
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
