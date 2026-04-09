# Tests for social_engineering_detector.py — Cyber Port Portfolio
# License: CC BY 4.0 — https://creativecommons.org/licenses/by/4.0/
# Copyright 2026 Cyber Port — github.com/hiagokinlevi
#
# Run with:  python -m pytest tests/test_social_engineering_detector.py -q

import sys
import os

# Allow import from the analyzers package without an installed package
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from analyzers.social_engineering_detector import (
    SENGFinding,
    SENGResult,
    analyze,
    analyze_many,
    _CHECK_WEIGHTS,
    _compute_risk_score,
    _phishing_likelihood,
    _extract_href_domain,
)


# ===========================================================================
# Helpers
# ===========================================================================

def _ids(result: SENGResult):
    """Return set of fired check IDs from a result."""
    return {f.check_id for f in result.findings}


def _finding(result: SENGResult, check_id: str) -> SENGFinding:
    """Return the SENGFinding for a specific check ID (raises if absent)."""
    for f in result.findings:
        if f.check_id == check_id:
            return f
    raise KeyError(f"{check_id} not in findings")


# ===========================================================================
# Module-level sanity checks
# ===========================================================================

def test_check_weights_keys():
    """All 7 check IDs must be present in _CHECK_WEIGHTS."""
    expected = {"SENG-001", "SENG-002", "SENG-003", "SENG-004",
                "SENG-005", "SENG-006", "SENG-007"}
    assert set(_CHECK_WEIGHTS.keys()) == expected


def test_check_weights_values_positive():
    for cid, w in _CHECK_WEIGHTS.items():
        assert w > 0, f"{cid} has non-positive weight"


def test_analyze_returns_sengresult():
    result = analyze("Hello world")
    assert isinstance(result, SENGResult)


def test_analyze_empty_string():
    result = analyze("")
    assert result.risk_score == 0
    assert result.phishing_likelihood == "LOW"
    assert result.findings == []


def test_analyze_raises_on_non_string():
    try:
        analyze(123)  # type: ignore
        assert False, "should have raised TypeError"
    except TypeError:
        pass


def test_analyze_raises_on_bad_content_type():
    try:
        analyze("hello", content_type="xml")  # type: ignore
        assert False, "should have raised ValueError"
    except ValueError:
        pass


def test_analyze_valid_text_content_type():
    result = analyze("Hello world", content_type="text")
    assert isinstance(result, SENGResult)


# ===========================================================================
# Helpers — _extract_href_domain
# ===========================================================================

def test_extract_href_domain_http():
    assert _extract_href_domain("http://evil.com/path") == "evil.com"


def test_extract_href_domain_https():
    assert _extract_href_domain("https://www.paypal.com/login") == "www.paypal.com"


def test_extract_href_domain_no_scheme():
    assert _extract_href_domain("/relative/path") is None


def test_extract_href_domain_mailto():
    assert _extract_href_domain("mailto:user@example.com") is None


def test_extract_href_domain_javascript():
    assert _extract_href_domain("javascript:void(0)") is None


def test_extract_href_domain_trailing_slash():
    assert _extract_href_domain("https://example.com/") == "example.com"


# ===========================================================================
# Helpers — _compute_risk_score and _phishing_likelihood
# ===========================================================================

def test_compute_risk_score_empty():
    assert _compute_risk_score([]) == 0


def test_compute_risk_score_single():
    f = SENGFinding("SENG-001", "HIGH", "t", "d", 25, [])
    assert _compute_risk_score([f]) == 25


def test_compute_risk_score_deduplication():
    # Two findings with same check ID — weight counted only once
    f1 = SENGFinding("SENG-001", "HIGH", "t", "d", 25, [])
    f2 = SENGFinding("SENG-001", "HIGH", "t", "d", 25, [])
    assert _compute_risk_score([f1, f2]) == 25


def test_compute_risk_score_capped_at_100():
    findings = [
        SENGFinding("SENG-001", "HIGH", "t", "d", 25, []),
        SENGFinding("SENG-002", "HIGH", "t", "d", 25, []),
        SENGFinding("SENG-003", "CRITICAL", "t", "d", 45, []),
        SENGFinding("SENG-004", "HIGH", "t", "d", 25, []),
    ]
    assert _compute_risk_score(findings) == 100


def test_compute_risk_score_multiple_distinct():
    findings = [
        SENGFinding("SENG-001", "HIGH", "t", "d", 25, []),
        SENGFinding("SENG-005", "MEDIUM", "t", "d", 15, []),
    ]
    assert _compute_risk_score(findings) == 40


def test_phishing_likelihood_high():
    assert _phishing_likelihood(60) == "HIGH"
    assert _phishing_likelihood(100) == "HIGH"
    assert _phishing_likelihood(75) == "HIGH"


def test_phishing_likelihood_medium():
    assert _phishing_likelihood(25) == "MEDIUM"
    assert _phishing_likelihood(59) == "MEDIUM"
    assert _phishing_likelihood(40) == "MEDIUM"


def test_phishing_likelihood_low():
    assert _phishing_likelihood(0) == "LOW"
    assert _phishing_likelihood(24) == "LOW"


# ===========================================================================
# SENG-001 — Urgency language
# ===========================================================================

def test_seng001_fires_expires_today():
    result = analyze("Your subscription expires today, please renew.")
    assert "SENG-001" in _ids(result)


def test_seng001_fires_act_now():
    result = analyze("Act now to secure your account.")
    assert "SENG-001" in _ids(result)


def test_seng001_fires_limited_time():
    result = analyze("This is a limited time offer just for you.")
    assert "SENG-001" in _ids(result)


def test_seng001_fires_account_suspended():
    result = analyze("Your account will be suspended unless you verify.")
    assert "SENG-001" in _ids(result)


def test_seng001_fires_within_24_hours():
    result = analyze("Please respond within 24 hours to avoid disruption.")
    assert "SENG-001" in _ids(result)


def test_seng001_fires_immediate_action():
    result = analyze("Immediate action required to protect your account.")
    assert "SENG-001" in _ids(result)


def test_seng001_fires_respond_immediately():
    result = analyze("Please respond immediately to avoid service interruption.")
    assert "SENG-001" in _ids(result)


def test_seng001_fires_last_chance():
    result = analyze("This is your last chance to claim this benefit.")
    assert "SENG-001" in _ids(result)


def test_seng001_case_insensitive():
    result = analyze("ACT NOW before it is too late!")
    assert "SENG-001" in _ids(result)


def test_seng001_evidence_collected():
    result = analyze("Act now! This is your last chance.")
    f = _finding(result, "SENG-001")
    assert "act now" in f.evidence
    assert "last chance" in f.evidence


def test_seng001_not_fired_clean_content():
    result = analyze("Welcome to our website. Enjoy your visit.")
    assert "SENG-001" not in _ids(result)


def test_seng001_severity_is_high():
    result = analyze("Act now to avoid losing access.")
    f = _finding(result, "SENG-001")
    assert f.severity == "HIGH"


def test_seng001_weight_correct():
    result = analyze("Act now.")
    f = _finding(result, "SENG-001")
    assert f.weight == 25


# ===========================================================================
# SENG-002 — Authority impersonation
# ===========================================================================

def test_seng002_fires_paypal_account():
    result = analyze("Your PayPal account has been locked. Please verify your identity.")
    assert "SENG-002" in _ids(result)


def test_seng002_fires_apple_verify():
    result = analyze("Apple requires you to verify your account immediately.")
    assert "SENG-002" in _ids(result)


def test_seng002_fires_microsoft_security_team():
    result = analyze("The Microsoft security team has detected unusual activity.")
    assert "SENG-002" in _ids(result)


def test_seng002_fires_google_account_information():
    result = analyze("Your Google account information needs to be updated.")
    assert "SENG-002" in _ids(result)


def test_seng002_fires_amazon_update_your():
    result = analyze("Update your Amazon payment details to continue shopping.")
    assert "SENG-002" in _ids(result)


def test_seng002_fires_netflix():
    result = analyze("Netflix: your account will be deactivated. Verify your details.")
    assert "SENG-002" in _ids(result)


def test_seng002_fires_facebook():
    result = analyze("Facebook: your account information must be verified.")
    assert "SENG-002" in _ids(result)


def test_seng002_fires_irs():
    result = analyze("The IRS requires you to update your tax account information.")
    assert "SENG-002" in _ids(result)


def test_seng002_fires_hmrc():
    result = analyze("HMRC: verify your account to receive your tax refund.")
    assert "SENG-002" in _ids(result)


def test_seng002_brand_only_does_not_fire():
    """Brand name without account language must NOT fire SENG-002."""
    result = analyze("I love shopping on Amazon for great deals.")
    assert "SENG-002" not in _ids(result)


def test_seng002_account_language_only_does_not_fire():
    """Account language without a brand name must NOT fire SENG-002."""
    result = analyze("Please verify your account details to continue.")
    assert "SENG-002" not in _ids(result)


def test_seng002_evidence_contains_brand_and_phrase():
    result = analyze("Your PayPal account needs verification.")
    f = _finding(result, "SENG-002")
    brands_in_ev = [e for e in f.evidence if e.startswith("brand:")]
    phrases_in_ev = [e for e in f.evidence if e.startswith("phrase:")]
    assert len(brands_in_ev) >= 1
    assert len(phrases_in_ev) >= 1


def test_seng002_case_insensitive_brand():
    result = analyze("PAYPAL requires you to update your account details.")
    assert "SENG-002" in _ids(result)


def test_seng002_severity_is_high():
    result = analyze("Your Microsoft account information is at risk. Verify your identity.")
    f = _finding(result, "SENG-002")
    assert f.severity == "HIGH"


def test_seng002_weight_correct():
    result = analyze("Your Google account needs attention.")
    f = _finding(result, "SENG-002")
    assert f.weight == 25


def test_seng002_instagram_fires():
    result = analyze("Instagram security team: your account has been flagged.")
    assert "SENG-002" in _ids(result)


def test_seng002_twitter_fires():
    result = analyze("Twitter requires you to verify your account ownership.")
    assert "SENG-002" in _ids(result)


# ===========================================================================
# SENG-003 — Credential harvesting
# ===========================================================================

def test_seng003_fires_password_type_attribute():
    html = '<form><input type="password" name="pwd"></form>'
    result = analyze(html, content_type="html")
    assert "SENG-003" in _ids(result)


def test_seng003_fires_password_type_single_quote():
    html = "<input type='password' />"
    result = analyze(html, content_type="html")
    assert "SENG-003" in _ids(result)


def test_seng003_fires_name_password():
    html = '<input name="password" type="text">'
    result = analyze(html, content_type="html")
    assert "SENG-003" in _ids(result)


def test_seng003_fires_name_passwd():
    html = '<input name="passwd">'
    result = analyze(html, content_type="html")
    assert "SENG-003" in _ids(result)


def test_seng003_fires_id_password():
    html = '<input id="password">'
    result = analyze(html, content_type="html")
    assert "SENG-003" in _ids(result)


def test_seng003_fires_enter_your_password_text():
    result = analyze("Please enter your password below.", content_type="text")
    assert "SENG-003" in _ids(result)


def test_seng003_fires_verify_your_account_text():
    result = analyze("Click here to verify your account and restore access.", content_type="text")
    assert "SENG-003" in _ids(result)


def test_seng003_fires_confirm_credentials():
    result = analyze("You must confirm your credentials to proceed.", content_type="text")
    assert "SENG-003" in _ids(result)


def test_seng003_fires_update_your_payment():
    result = analyze("Update your payment information immediately.", content_type="text")
    assert "SENG-003" in _ids(result)


def test_seng003_fires_reenter_password():
    result = analyze("Please re-enter your password to confirm.", content_type="text")
    assert "SENG-003" in _ids(result)


def test_seng003_fires_text_phrase_in_html_mode():
    """Text phrases should also fire in html mode."""
    result = analyze("Enter your password to continue.", content_type="html")
    assert "SENG-003" in _ids(result)


def test_seng003_password_field_in_text_mode_does_not_fire_on_attribute():
    """HTML attribute check should NOT run in text mode."""
    content = 'Someone wrote: type="password" in their notes'
    result = analyze(content, content_type="text")
    # Only text phrases matter in text mode; raw attribute string should NOT trigger
    # (the text has no matching text phrase either)
    assert "SENG-003" not in _ids(result)


def test_seng003_severity_is_critical():
    html = '<input type="password">'
    result = analyze(html, content_type="html")
    f = _finding(result, "SENG-003")
    assert f.severity == "CRITICAL"


def test_seng003_weight_correct():
    html = '<input type="password">'
    result = analyze(html)
    f = _finding(result, "SENG-003")
    assert f.weight == 45


def test_seng003_no_credential_indicators_no_fire():
    result = analyze("<form><input type='text' name='username'></form>")
    assert "SENG-003" not in _ids(result)


# ===========================================================================
# SENG-004 — Fear / threat language
# ===========================================================================

def test_seng004_fires_compromised():
    result = analyze("Your account has been compromised. Change your password.")
    assert "SENG-004" in _ids(result)


def test_seng004_fires_unauthorized_access():
    result = analyze("Unauthorized access detected on your account.")
    assert "SENG-004" in _ids(result)


def test_seng004_fires_suspicious_activity():
    result = analyze("We detected suspicious activity on your profile.")
    assert "SENG-004" in _ids(result)


def test_seng004_fires_account_suspended():
    # "account suspended" is the exact spec phrase — use it verbatim
    result = analyze("Notice: account suspended pending review of your activity.")
    assert "SENG-004" in _ids(result)


def test_seng004_fires_account_will_be_terminated():
    result = analyze("Your account will be terminated if no action is taken.")
    assert "SENG-004" in _ids(result)


def test_seng004_fires_security_breach():
    result = analyze("A security breach has exposed your credentials.")
    assert "SENG-004" in _ids(result)


def test_seng004_fires_illegal_activity():
    result = analyze("Illegal activity has been detected linked to your IP address.")
    assert "SENG-004" in _ids(result)


def test_seng004_fires_fraudulent_activity():
    result = analyze("Fraudulent activity was detected on your payment method.")
    assert "SENG-004" in _ids(result)


def test_seng004_case_insensitive():
    result = analyze("SUSPICIOUS ACTIVITY was found on your account.")
    assert "SENG-004" in _ids(result)


def test_seng004_not_fired_clean():
    result = analyze("Everything looks great on your account today!")
    assert "SENG-004" not in _ids(result)


def test_seng004_severity_is_high():
    result = analyze("Unauthorized access has been detected.")
    f = _finding(result, "SENG-004")
    assert f.severity == "HIGH"


def test_seng004_weight_correct():
    result = analyze("Suspicious activity on your account.")
    f = _finding(result, "SENG-004")
    assert f.weight == 25


def test_seng004_evidence_collected():
    result = analyze("Suspicious activity and security breach detected.")
    f = _finding(result, "SENG-004")
    assert "suspicious activity" in f.evidence
    assert "security breach" in f.evidence


# ===========================================================================
# SENG-005 — Reward / prize language
# ===========================================================================

def test_seng005_fires_you_have_won():
    result = analyze("You have won our monthly sweepstakes!")
    assert "SENG-005" in _ids(result)


def test_seng005_fires_youve_won():
    result = analyze("You've won a brand-new smartphone!")
    assert "SENG-005" in _ids(result)


def test_seng005_fires_selected_for_reward():
    result = analyze("You have been selected for a reward program.")
    assert "SENG-005" in _ids(result)


def test_seng005_fires_claim_your_prize():
    result = analyze("Click here to claim your prize before it expires.")
    assert "SENG-005" in _ids(result)


def test_seng005_fires_you_have_been_chosen():
    result = analyze("You have been chosen as our lucky winner.")
    assert "SENG-005" in _ids(result)


def test_seng005_fires_congratulations():
    result = analyze("Congratulations! Your entry has been selected.")
    assert "SENG-005" in _ids(result)


def test_seng005_fires_free_gift():
    result = analyze("Receive a free gift with every purchase over $50.")
    assert "SENG-005" in _ids(result)


def test_seng005_fires_exclusive_offer():
    result = analyze("This exclusive offer is only available to you.")
    assert "SENG-005" in _ids(result)


def test_seng005_fires_special_reward():
    result = analyze("You qualify for a special reward this month.")
    assert "SENG-005" in _ids(result)


def test_seng005_not_fired_clean():
    result = analyze("Thank you for your order. We hope you enjoy your purchase.")
    assert "SENG-005" not in _ids(result)


def test_seng005_severity_is_medium():
    result = analyze("Congratulations, you have won!")
    f = _finding(result, "SENG-005")
    assert f.severity == "MEDIUM"


def test_seng005_weight_correct():
    result = analyze("Congratulations! Claim your prize today.")
    f = _finding(result, "SENG-005")
    assert f.weight == 15


# ===========================================================================
# SENG-006 — Deceptive link pattern
# ===========================================================================

def test_seng006_fires_mismatched_domains():
    html = '<a href="http://evil.com/steal">Visit paypal.com for your refund</a>'
    result = analyze(html, content_type="html")
    assert "SENG-006" in _ids(result)


def test_seng006_fires_https_mismatch():
    html = '<a href="https://attacker.net/phish">Secure login at google.com</a>'
    result = analyze(html, content_type="html")
    assert "SENG-006" in _ids(result)


def test_seng006_same_domain_does_not_fire():
    """Same domain in text and href must NOT trigger SENG-006."""
    html = '<a href="https://paypal.com/login">paypal.com login page</a>'
    result = analyze(html, content_type="html")
    assert "SENG-006" not in _ids(result)


def test_seng006_relative_url_does_not_fire():
    """Relative href with domain-like display text must NOT fire."""
    html = '<a href="/login">paypal.com</a>'
    result = analyze(html, content_type="html")
    assert "SENG-006" not in _ids(result)


def test_seng006_no_domain_in_display_text_does_not_fire():
    """Plain text anchor without domain-like content must NOT fire."""
    html = '<a href="http://evil.com/steal">Click here to log in</a>'
    result = analyze(html, content_type="html")
    assert "SENG-006" not in _ids(result)


def test_seng006_plain_text_mode_skips_check():
    """Deceptive link check must be skipped entirely in text mode."""
    content = '<a href="http://evil.com">paypal.com</a>'
    result = analyze(content, content_type="text")
    assert "SENG-006" not in _ids(result)


def test_seng006_evidence_describes_mismatch():
    html = '<a href="http://evil.com/page">Visit paypal.com</a>'
    result = analyze(html, content_type="html")
    f = _finding(result, "SENG-006")
    assert len(f.evidence) >= 1
    assert "paypal.com" in f.evidence[0]
    assert "evil.com" in f.evidence[0]


def test_seng006_multiple_deceptive_links():
    html = (
        '<a href="http://evil.com/a">paypal.com</a> '
        '<a href="http://bad.net/b">microsoft.com</a>'
    )
    result = analyze(html, content_type="html")
    f = _finding(result, "SENG-006")
    assert len(f.evidence) >= 2


def test_seng006_subdomain_same_base_does_not_fire():
    """href subdomain ending with displayed domain should NOT fire."""
    html = '<a href="http://login.paypal.com/secure">paypal.com</a>'
    result = analyze(html, content_type="html")
    assert "SENG-006" not in _ids(result)


def test_seng006_severity_is_high():
    html = '<a href="http://malicious.ru">amazon.com</a>'
    result = analyze(html, content_type="html")
    f = _finding(result, "SENG-006")
    assert f.severity == "HIGH"


def test_seng006_weight_correct():
    html = '<a href="http://phish.io">google.com secure login</a>'
    result = analyze(html)
    f = _finding(result, "SENG-006")
    assert f.weight == 25


def test_seng006_mailto_href_does_not_fire():
    html = '<a href="mailto:attacker@evil.com">paypal.com</a>'
    result = analyze(html, content_type="html")
    assert "SENG-006" not in _ids(result)


# ===========================================================================
# SENG-007 — Excessive PII collection
# ===========================================================================

def test_seng007_fires_with_3_pii_categories():
    content = "Please enter your full name, phone number, and email address."
    result = analyze(content, content_type="text")
    assert "SENG-007" in _ids(result)


def test_seng007_fires_with_4_pii_categories():
    content = "Enter your full name, phone number, email address, and street address."
    result = analyze(content, content_type="text")
    assert "SENG-007" in _ids(result)


def test_seng007_does_not_fire_with_2_pii_categories():
    """Only 2 PII fields must NOT fire SENG-007."""
    content = "Enter your full name and phone number to subscribe."
    result = analyze(content, content_type="text")
    assert "SENG-007" not in _ids(result)


def test_seng007_does_not_fire_with_1_pii_category():
    content = "Enter your email address to subscribe."
    result = analyze(content, content_type="text")
    assert "SENG-007" not in _ids(result)


def test_seng007_does_not_fire_with_no_pii():
    content = "Welcome to our website. Click here to learn more."
    result = analyze(content, content_type="text")
    assert "SENG-007" not in _ids(result)


def test_seng007_fires_ssn_dob_address():
    content = "We need your SSN, date of birth, and street address."
    result = analyze(content, content_type="text")
    assert "SENG-007" in _ids(result)


def test_seng007_fires_social_security_birthday_phone():
    content = "Enter your social security number, birthday, and mobile number."
    result = analyze(content, content_type="text")
    assert "SENG-007" in _ids(result)


def test_seng007_fires_with_all_6_categories():
    content = (
        "Provide your SSN, date of birth, full name, "
        "street address, phone number, and e-mail address."
    )
    result = analyze(content, content_type="text")
    assert "SENG-007" in _ids(result)
    f = _finding(result, "SENG-007")
    assert len(f.evidence) == 6


def test_seng007_severity_is_high():
    content = "Please provide your full name, phone number, and email address."
    result = analyze(content, content_type="text")
    f = _finding(result, "SENG-007")
    assert f.severity == "HIGH"


def test_seng007_weight_correct():
    content = "Enter your SSN, date of birth, and phone number."
    result = analyze(content, content_type="text")
    f = _finding(result, "SENG-007")
    assert f.weight == 20


def test_seng007_first_name_last_name_counts_as_one_category():
    """first name + last name should count as a SINGLE category."""
    content = "Enter your first name, last name, and phone number."
    result = analyze(content, content_type="text")
    # Only 2 categories (full_name + phone) — should NOT fire
    assert "SENG-007" not in _ids(result)


def test_seng007_email_address_pattern():
    content = "Provide your email address, phone, and street address."
    result = analyze(content, content_type="text")
    assert "SENG-007" in _ids(result)


# ===========================================================================
# SENGResult methods
# ===========================================================================

def test_to_dict_structure():
    result = analyze("Act now! Your account has been compromised.", content_type="text")
    d = result.to_dict()
    assert "risk_score" in d
    assert "phishing_likelihood" in d
    assert "findings" in d
    assert isinstance(d["findings"], list)


def test_to_dict_finding_keys():
    html = '<input type="password">'
    result = analyze(html)
    d = result.to_dict()
    for finding_dict in d["findings"]:
        for key in ("check_id", "severity", "title", "detail", "weight", "evidence"):
            assert key in finding_dict


def test_to_dict_risk_score_matches():
    result = analyze("Act now!")
    d = result.to_dict()
    assert d["risk_score"] == result.risk_score


def test_summary_contains_likelihood():
    result = analyze("Act now!")
    s = result.summary()
    assert result.phishing_likelihood in s


def test_summary_contains_risk_score():
    result = analyze("Act now!")
    s = result.summary()
    assert str(result.risk_score) in s


def test_summary_is_string():
    result = analyze("")
    assert isinstance(result.summary(), str)


def test_by_severity_groups_correctly():
    html = (
        "Act now! Your account has been compromised. "
        '<input type="password"> '
        "Congratulations, you have won!"
    )
    result = analyze(html)
    grouped = result.by_severity()
    assert isinstance(grouped, dict)
    # CRITICAL finding should be present
    if "CRITICAL" in grouped:
        for f in grouped["CRITICAL"]:
            assert f.severity == "CRITICAL"
    if "HIGH" in grouped:
        for f in grouped["HIGH"]:
            assert f.severity == "HIGH"


def test_by_severity_empty_result():
    result = analyze("")
    grouped = result.by_severity()
    assert grouped == {}


# ===========================================================================
# Risk score and likelihood integration
# ===========================================================================

def test_risk_score_single_check_medium():
    result = analyze("Congratulations! You have won a free gift.")
    assert result.risk_score == 15
    assert result.phishing_likelihood == "LOW"


def test_risk_score_single_check_high():
    result = analyze("Act now before it expires today!")
    assert result.risk_score == 25
    assert result.phishing_likelihood == "MEDIUM"


def test_risk_score_critical_alone():
    html = '<input type="password">'
    result = analyze(html)
    assert result.risk_score == 45
    assert result.phishing_likelihood == "MEDIUM"


def test_risk_score_capped_at_100():
    html = (
        "Act now! Your PayPal account has been compromised. "
        '<input type="password"> '
        "Unauthorized access detected. "
        "Congratulations, claim your prize! "
        '<a href="http://evil.com">paypal.com refund</a>'
    )
    result = analyze(html)
    assert result.risk_score <= 100


def test_phishing_likelihood_high_scenario():
    html = (
        "Immediate action required. "
        "Your Microsoft account has been compromised. "
        "Please verify your account to continue. "
        '<input type="password">'
    )
    result = analyze(html)
    assert result.phishing_likelihood == "HIGH"


# ===========================================================================
# analyze_many
# ===========================================================================

def test_analyze_many_returns_list():
    results = analyze_many(["hello", "world"])
    assert isinstance(results, list)
    assert len(results) == 2


def test_analyze_many_each_is_sengresult():
    results = analyze_many(["Act now!", "Congratulations you have won!"])
    for r in results:
        assert isinstance(r, SENGResult)


def test_analyze_many_empty_list():
    results = analyze_many([])
    assert results == []


def test_analyze_many_preserves_order():
    contents = [
        "Act now!",  # should fire SENG-001
        "Hello world",  # clean
        "Congratulations! Claim your prize!",  # SENG-005
    ]
    results = analyze_many(contents)
    assert "SENG-001" in _ids(results[0])
    assert _ids(results[1]) == set()
    assert "SENG-005" in _ids(results[2])


def test_analyze_many_text_mode():
    contents = ["Enter your password here.", "Hello world"]
    results = analyze_many(contents, content_type="text")
    assert "SENG-003" in _ids(results[0])
    assert "SENG-003" not in _ids(results[1])


# ===========================================================================
# Combined / real-world scenario tests
# ===========================================================================

def test_combined_classic_phishing_email():
    """Typical PayPal phishing email hits SENG-001, 002, 003, 004."""
    email = (
        "Dear customer,\n\n"
        "Unauthorized access has been detected on your PayPal account. "
        "Your account will be suspended unless you verify your account "
        "within 24 hours.\n\n"
        "Please enter your password to confirm your identity.\n\n"
        "Immediate action required.\n\n"
        "The PayPal security team"
    )
    result = analyze(email, content_type="text")
    fired = _ids(result)
    assert "SENG-001" in fired
    assert "SENG-002" in fired
    assert "SENG-003" in fired
    assert "SENG-004" in fired
    assert result.phishing_likelihood == "HIGH"


def test_combined_irs_tax_scam():
    """IRS impersonation scam email."""
    email = (
        "The IRS has detected illegal activity associated with your account. "
        "Your account will be terminated if you do not update your account information "
        "immediately. Respond immediately to avoid prosecution."
    )
    result = analyze(email, content_type="text")
    fired = _ids(result)
    assert "SENG-001" in fired
    assert "SENG-002" in fired
    assert "SENG-004" in fired


def test_combined_prize_scam_html():
    """Lottery scam page with deceptive link."""
    html = (
        "<p>Congratulations! You have been chosen to claim your prize!</p>"
        "<p>This exclusive offer expires today. Act now!</p>"
        '<p><a href="http://scam.ru/claim">Visit amazon.com to claim</a></p>'
    )
    result = analyze(html, content_type="html")
    fired = _ids(result)
    assert "SENG-005" in fired
    assert "SENG-001" in fired
    assert "SENG-006" in fired


def test_combined_identity_theft_form():
    """Fake identity verification page collecting excessive PII + credentials."""
    html = (
        "<form>"
        '<input type="text" name="full_name" placeholder="Full Name">'
        '<input type="text" name="phone" placeholder="Phone Number">'
        '<input type="text" name="street" placeholder="Street Address">'
        '<input type="text" name="ssn" placeholder="Social Security Number">'
        '<input type="password" name="password">'
        "</form>"
    )
    result = analyze(html, content_type="html")
    fired = _ids(result)
    assert "SENG-003" in fired
    assert "SENG-007" in fired


def test_combined_clean_legitimate_page():
    """A well-formed legitimate page should fire no checks."""
    html = (
        "<html><body>"
        "<h1>Welcome to Our Store</h1>"
        "<p>Browse our catalog and find great products.</p>"
        '<a href="https://shop.example.com/cart">View your cart on shop.example.com</a>'
        "</body></html>"
    )
    result = analyze(html, content_type="html")
    assert result.phishing_likelihood == "LOW"
    assert result.risk_score == 0


def test_combined_all_checks_fire():
    """Construct content that triggers all 7 checks."""
    html = (
        # SENG-001 urgency
        "Act now — immediate action required. "
        # SENG-002 authority
        "Your Microsoft account information must be verified. "
        # SENG-004 fear
        "Unauthorized access has been detected. "
        # SENG-005 reward
        "Congratulations, you have won a free gift! "
        # SENG-003 credential HTML
        '<input type="password"> '
        # SENG-006 deceptive link
        '<a href="http://evil.net/steal">paypal.com secure login</a> '
        # SENG-007 PII
        "Provide your SSN, date of birth, full name, phone number, "
        "street address, and email address."
    )
    result = analyze(html, content_type="html")
    fired = _ids(result)
    for check_id in ("SENG-001", "SENG-002", "SENG-003", "SENG-004",
                     "SENG-005", "SENG-006", "SENG-007"):
        assert check_id in fired, f"{check_id} did not fire"
    assert result.risk_score == 100  # capped
    assert result.phishing_likelihood == "HIGH"
