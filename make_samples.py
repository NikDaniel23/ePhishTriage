"""Generates three synthetic test emails and the offline intel file.

Everything here is fake and safe:
  - "NusaBank" is a fictional bank
  - IPs come from ranges reserved for documentation (203.0.113.x, 198.51.100.x)
  - the "attachment" is a harmless text snippet

Run:  python make_samples.py
"""
import hashlib
import json
from email.message import EmailMessage
from pathlib import Path

OUT = Path(__file__).parent / "samples"
OUT.mkdir(exist_ok=True)
intel: dict = {}


def base(received: list[str], auth: str) -> EmailMessage:
    msg = EmailMessage()
    for r in received:  # newest first, like a real mail server writes them
        msg["Received"] = r
    msg["Authentication-Results"] = auth
    return msg


# ---------------------------------------------------------------- 1. obvious
m = base(
    ["from mx.corp.example (mx.corp.example [10.0.0.5]) by mailbox.corp.example; "
     "Mon, 9 Nov 2026 09:14:07 +0800",
     "from mail.secure-verify.top (unknown [203.0.113.45]) by mx.corp.example; "
     "Mon, 9 Nov 2026 09:14:05 +0800"],
    "mx.corp.example; spf=fail smtp.mailfrom=secure-verify.top; dkim=none; "
    "dmarc=fail header.from=secure-verify.top",
)
m["Return-Path"] = "<bounce@secure-verify.top>"
m["From"] = '"NusaBank Security" <alert@secure-verify.top>'
m["Reply-To"] = "sample_nusabank_helpdesk@gmail.com"
m["To"] = "staff@corp.example"
m["Subject"] = "URGENT: Your NusaBank account will be suspended within 24 hours"
m["Date"] = "Mon, 9 Nov 2026 09:14:02 +0800"
m["Message-ID"] = "<8841@secure-verify.top>"
m.set_content(
    "Dear customer,\n\nWe detected unusual activity. Verify your account "
    "immediately or it will be suspended within 24 hours:\n"
    "http://nusabank-com-my.secure-verify.top/login?id=8841\n\nNusaBank Security"
)
m.add_alternative(
    "<p>Dear customer,</p><p>We detected unusual activity. Verify your account "
    "immediately or it will be suspended within 24 hours.</p>"
    '<p><a href="http://nusabank-com-my.secure-verify.top/login?id=8841">'
    "https://www.nusabank.com.my/login</a></p><p>NusaBank Security</p>",
    subtype="html",
)
attachment = b"<html><!-- harmless placeholder for a fake login page --></html>"
m.add_attachment(attachment, maintype="text", subtype="html",
                 filename="Statement.pdf.html")
(OUT / "01_obvious_phish.eml").write_bytes(bytes(m))
intel["domain:secure-verify.top"] = {"malicious": 9, "suspicious": 2, "age_days": 6}
intel["ip:203.0.113.45"] = {"abuse_score": 87, "country": "??", "isp": "Example Hosting"}
intel[f"hash:{hashlib.sha256(attachment).hexdigest()}"] = {"malicious": 14}

# ----------------------------------------------------------------- 2. benign
m = base(
    ["from mta.kldesignmeetup.example (mta.kldesignmeetup.example [198.51.100.20]) "
     "by mx.corp.example; Tue, 10 Nov 2026 10:00:03 +0800"],
    "mx.corp.example; spf=pass smtp.mailfrom=kldesignmeetup.example; "
    "dkim=pass header.d=kldesignmeetup.example; "
    "dmarc=pass header.from=kldesignmeetup.example",
)
m["Return-Path"] = "<news@kldesignmeetup.example>"
m["From"] = '"KL Design Meetup" <news@kldesignmeetup.example>'
m["To"] = "staff@corp.example"
m["Subject"] = "November meetup: motion design showcase"
m["Date"] = "Tue, 10 Nov 2026 10:00:00 +0800"
m["Message-ID"] = "<nov-2026@kldesignmeetup.example>"
m.set_content(
    "Hi,\n\nOur November meetup is on the 21st. Details and RSVP:\n"
    "https://kldesignmeetup.example/events/november\n\nSee you there."
)
(OUT / "02_benign_newsletter.eml").write_bytes(bytes(m))
intel["domain:kldesignmeetup.example"] = {"malicious": 0, "suspicious": 0, "age_days": 2140}
intel["ip:198.51.100.20"] = {"abuse_score": 0, "country": "MY", "isp": "Example Mail"}

# ----------------------------------------------------------------- 3. tricky
# Passes SPF, DKIM and DMARC - the attacker is sending from a mailbox or
# domain they control. Authentication alone would call this clean.
m = base(
    ["from smtp.partner-logistics.example (smtp.partner-logistics.example "
     "[198.51.100.77]) by mx.corp.example; Tue, 10 Nov 2026 14:22:10 +0800"],
    "mx.corp.example; spf=pass smtp.mailfrom=partner-logistics.example; "
    "dkim=pass header.d=partner-logistics.example; "
    "dmarc=pass header.from=partner-logistics.example",
)
m["Return-Path"] = "<aina@partner-logistics.example>"
m["From"] = '"Aina (HR)" <aina@partner-logistics.example>'
m["Reply-To"] = "aina.hr@mailbox-relay.example"
m["To"] = "staff@corp.example"
m["Subject"] = "Shared document: 2027 salary adjustment"
m["Date"] = "Tue, 10 Nov 2026 14:22:05 +0800"
m["Message-ID"] = "<doc-5521@partner-logistics.example>"
m.set_content(
    "Hi,\n\nPlease review the 2027 salary adjustment document before 5pm today:\n"
    "https://docs-portal-share.example/view?id=5521\n\nThanks,\nAina"
)
(OUT / "03_tricky_shared_doc.eml").write_bytes(bytes(m))
intel["domain:partner-logistics.example"] = {"malicious": 0, "suspicious": 0, "age_days": 1890}
intel["domain:docs-portal-share.example"] = {"malicious": 0, "suspicious": 0, "age_days": 12}
intel["domain:mailbox-relay.example"] = {"malicious": 0, "suspicious": 0, "age_days": 400}
intel["ip:198.51.100.77"] = {"abuse_score": 3, "country": "MY", "isp": "Example Net"}

# -------------------------------------------------- 4. Malay tax-refund lure
# The classic Malaysian scam: "LHDN owes you a refund, confirm your bank
# details". Written in Bahasa Melayu to exercise the Malay keyword lists.
# Tricks inside:
#   - display name says LHDN, address is a look-alike domain
#   - link text shows the real mytax.hasil.gov.my, the href goes elsewhere
#   - "https://mytax.hasil.gov.my@198.51.100.99/..." - everything before the
#     @ is ignored by the browser, so it really goes to a bare IP
# All domains are .example and all IPs are documentation ranges: safe.
m = base(
    ["from mail.lhdn-refund.example (unknown [203.0.113.88]) by mx.corp.example; "
     "Wed, 11 Nov 2026 08:03:12 +0800"],
    "mx.corp.example; spf=softfail smtp.mailfrom=lhdn-refund.example; "
    "dkim=none; dmarc=none header.from=lhdn-refund.example",
)
m["Return-Path"] = "<notis@lhdn-refund.example>"
m["From"] = '"LHDN Malaysia - Unit Bayaran Balik" <notis@lhdn-refund.example>'
m["Reply-To"] = "bayaranbalik.lhdn@mailbox-relay.example"
m["To"] = "staff@corp.example"
m["Subject"] = "Notis Bayaran Balik Cukai 2026 - Tindakan Segera Diperlukan"
m["Date"] = "Wed, 11 Nov 2026 08:03:09 +0800"
m["Message-ID"] = "<rb-2026-7730@lhdn-refund.example>"
m.set_content(
    "Tuan/Puan,\n\n"
    "Anda layak menerima bayaran balik cukai sebanyak RM1,284.50 bagi tahun "
    "taksiran 2025. Sila sahkan akaun bank anda dalam masa 24 jam, jika tidak "
    "tuntutan anda akan digantung.\n\n"
    "Log masuk dengan ID pengguna dan kata laluan MyTax anda, kemudian masukkan "
    "nombor TAC yang dihantar ke telefon anda:\n"
    "https://mytax.hasil.gov.my@198.51.100.99/tuntutan/7730\n\n"
    "Unit Bayaran Balik\nLembaga Hasil Dalam Negeri Malaysia"
)
m.add_alternative(
    "<p>Tuan/Puan,</p>"
    "<p>Anda layak menerima bayaran balik cukai sebanyak <b>RM1,284.50</b> bagi "
    "tahun taksiran 2025. Sila sahkan akaun bank anda <b>dalam masa 24 jam</b>, "
    "jika tidak tuntutan anda akan digantung.</p>"
    "<p>Log masuk dengan ID pengguna dan kata laluan MyTax anda, kemudian "
    "masukkan nombor TAC yang dihantar ke telefon anda:</p>"
    '<p><a href="https://lhdn-refund.example/mytax/login?ref=7730">'
    "https://mytax.hasil.gov.my/tuntutan</a></p>"
    '<p>Atau: <a href="https://mytax.hasil.gov.my@198.51.100.99/tuntutan/7730">'
    "Tuntut sekarang</a></p>"
    "<p>Unit Bayaran Balik<br>Lembaga Hasil Dalam Negeri Malaysia</p>",
    subtype="html",
)
(OUT / "04_malay_tax_refund.eml").write_bytes(bytes(m))
intel["domain:lhdn-refund.example"] = {"malicious": 4, "suspicious": 1, "age_days": 3}
intel["ip:203.0.113.88"] = {"abuse_score": 64, "country": "??", "isp": "Example VPS"}
intel["ip:198.51.100.99"] = {"abuse_score": 52, "country": "??", "isp": "Example VPS"}

# ------------------------------------------------- 5. BEC: CEO gift cards
# Business Email Compromise. No link, no attachment, and it comes from a
# real webmail provider, so SPF/DKIM/DMARC all PASS. Only the situation is
# wrong: our CEO's name on a Gmail account, asking for gift-card codes,
# quietly. The mailbox name is made up; the IP is a documentation range.
m = base(
    ["from mail-sor-f41.google.com (mail-sor-f41.google.com [192.0.2.41]) by "
     "mx.corp.example; Thu, 12 Nov 2026 10:02:17 +0800"],
    "mx.corp.example; spf=pass smtp.mailfrom=gmail.com; dkim=pass header.d=gmail.com; "
    "dmarc=pass header.from=gmail.com",
)
m["Return-Path"] = "<sample_dato_rahman_ceo@gmail.com>"
m["From"] = "\"Dato' Rahman Ismail\" <sample_dato_rahman_ceo@gmail.com>"
m["To"] = "aisyah.hr@corp.example"
m["Subject"] = "Quick favour"
m["Date"] = "Thu, 12 Nov 2026 10:02:11 +0800"
m["Message-ID"] = "<CAF7x2-sample-0001@mail.gmail.com>"
m.set_content(
    "Aisyah,\n\n"
    "Are you at your desk? I need a quick favour. I'm in a meeting with the board "
    "and can't talk.\n\n"
    "Please buy 10 Google Play gift cards (RM500 each) for a client appreciation "
    "event. Scratch the back and email me photos of the codes. I will sort out the "
    "claim with Finance later.\n\n"
    "Keep this confidential until I announce it. Reply only by email.\n\n"
    "Rahman\nSent from my iPhone"
)
(OUT / "05_bec_ceo_gift_cards.eml").write_bytes(bytes(m))
intel["ip:192.0.2.41"] = {"abuse_score": 0, "country": "US", "isp": "Example Webmail"}

# ----------------------------- 6. BEC: bank-change from a look-alike domain
# c0rp.example (zero, not o) was registered 4 days ago. The attacker set up
# SPF/DKIM/DMARC for it, so authentication passes for their own domain.
m = base(
    ["from mail.c0rp.example (mail.c0rp.example [198.51.100.66]) by mx.corp.example; "
     "Thu, 12 Nov 2026 14:41:30 +0800"],
    "mx.corp.example; spf=pass smtp.mailfrom=c0rp.example; dkim=pass header.d=c0rp.example; "
    "dmarc=pass header.from=c0rp.example",
)
m["Return-Path"] = "<accounts@c0rp.example>"
m["From"] = '"Finance Department" <accounts@c0rp.example>'
m["To"] = "payables@corp.example"
m["Subject"] = "Updated bank details for INV-2026-0912 / Butiran bank baharu"
m["Date"] = "Thu, 12 Nov 2026 14:41:22 +0800"
m["Message-ID"] = "<inv-0912@c0rp.example>"
m.set_content(
    "Hi Payables team,\n\n"
    "Please note our banking details have changed following our audit. For invoice "
    "INV-2026-0912 (RM48,250.00), please process the payment today to the new bank "
    "account below and discard the old details.\n\n"
    "Bank: Example Bank Berhad\nAccount name: Corp Example Sdn Bhd\n"
    "Account number: 0000-0000-0000 (sample)\n\n"
    "Sila buat bayaran segera ke akaun bank baru di atas.\n\n"
    "Thank you,\nFinance Department"
)
(OUT / "06_bec_bank_change_lookalike.eml").write_bytes(bytes(m))
intel["domain:c0rp.example"] = {"malicious": 0, "suspicious": 0, "age_days": 4}
intel["ip:198.51.100.66"] = {"abuse_score": 12, "country": "MY", "isp": "Example VPS"}

# (07_thread_reply_lookalike_link.eml is a hand-supplied challenge email:
#  it is kept in samples/ as-is and not generated here.)

# ------------------------------------------------- 8. Quishing: QR code
# The link is a PICTURE. There is no URL in the email for a scanner to
# check, and the victim opens it on a phone, outside company protection.
try:
    import cv2

    qr = cv2.QRCodeEncoder.create().encode("https://m365-reauth.example/mfa?u=staff")
    qr = cv2.resize(qr, None, fx=8, fy=8, interpolation=cv2.INTER_NEAREST)
    qr = cv2.copyMakeBorder(qr, 32, 32, 32, 32, cv2.BORDER_CONSTANT, value=255)
    qr_png = cv2.imencode(".png", qr)[1].tobytes()
except ImportError:
    qr_png = None
    print("opencv-python-headless not installed: skipping the QR sample")

if qr_png:
    m = base(
        ["from out.m365-notice.example (out.m365-notice.example [198.51.100.140]) by "
         "mx.corp.example; Fri, 13 Nov 2026 08:30:11 +0800"],
        "mx.corp.example; spf=pass smtp.mailfrom=m365-notice.example; "
        "dkim=pass header.d=m365-notice.example; dmarc=pass header.from=m365-notice.example",
    )
    m["Return-Path"] = "<no-reply@m365-notice.example>"
    m["From"] = '"Microsoft 365 Security" <no-reply@m365-notice.example>'
    m["To"] = "staff@corp.example"
    m["Subject"] = "Your multi-factor authentication expires today"
    m["Date"] = "Fri, 13 Nov 2026 08:30:05 +0800"
    m["Message-ID"] = "<mfa-7781@m365-notice.example>"
    m.set_content(
        "Your multi-factor authentication expires today.\n\n"
        "To keep access to email and Teams, scan the QR code in this message with "
        "your phone camera and follow the steps.\n\nMicrosoft 365 Security"
    )
    m.add_alternative(
        "<p>Your multi-factor authentication expires today.</p>"
        "<p>To keep access to email and Teams, scan the QR code below with your phone "
        'camera and follow the steps.</p><p><img src="cid:mfaqr" alt="QR code" '
        'width="220"></p><p>Microsoft 365 Security</p>',
        subtype="html",
    )
    m.get_payload()[1].add_related(qr_png, "image", "png", cid="<mfaqr>", filename="mfa-qr.png")
    (OUT / "08_quishing_qr_code.eml").write_bytes(bytes(m))
    intel["domain:m365-notice.example"] = {"malicious": 0, "suspicious": 0, "age_days": 9}
    intel["domain:m365-reauth.example"] = {"malicious": 2, "suspicious": 1, "age_days": 2}
    intel["ip:198.51.100.140"] = {"abuse_score": 21, "country": "??", "isp": "Example VPS"}

# ----------------------------------- 9. Fake login page as an HTML attachment
# The phishing page is not on a website (which could be blocked): it IS the
# attachment. Opened locally, it posts the password to the attacker.
# The form below is inert training markup pointing at a reserved .example name.
login_page = (
    "<!doctype html><html><head><title>Voicemail</title></head><body>"
    "<h3>Sign in to play your voicemail</h3>"
    '<form method="post" action="https://collect.voice-notify-login.example/save">'
    '<input type="email" name="user" value="staff@corp.example">'
    '<input type="password" name="pass" placeholder="Password">'
    '<button type="submit">Play message</button></form>'
    "<script>var t = atob('VHJhaW5pbmcgc2FtcGxl'); document.title = t;</script>"
    "</body></html>"
).encode()
m = base(
    ["from mta.voice-notify.example (mta.voice-notify.example [198.51.100.151]) by "
     "mx.corp.example; Fri, 13 Nov 2026 11:12:40 +0800"],
    "mx.corp.example; spf=pass smtp.mailfrom=voice-notify.example; "
    "dkim=pass header.d=voice-notify.example; dmarc=none",
)
m["Return-Path"] = "<vm@voice-notify.example>"
m["From"] = '"Voicemail Service" <vm@voice-notify.example>'
m["To"] = "staff@corp.example"
m["Subject"] = "New voicemail (0:42) from +60 3-5550 0142"
m["Date"] = "Fri, 13 Nov 2026 11:12:33 +0800"
m["Message-ID"] = "<vm-0412@voice-notify.example>"
m.set_content(
    "You received a new voicemail.\n\nCaller: +60 3-5550 0142\nLength: 0:42\n\n"
    "Open the attached file to listen."
)
m.add_attachment(login_page, maintype="text", subtype="html", filename="Voicemail_0412.html")
(OUT / "09_html_attachment_login.eml").write_bytes(bytes(m))
intel[f"hash:{hashlib.sha256(login_page).hexdigest()}"] = {"malicious": 0}
intel["domain:voice-notify.example"] = {"malicious": 0, "suspicious": 0, "age_days": 35}
intel["ip:198.51.100.151"] = {"abuse_score": 8, "country": "??", "isp": "Example VPS"}

(OUT / "mock_intel.json").write_text(json.dumps(intel, indent=2))
print(f"Wrote sample emails and mock_intel.json to {OUT}")

# =====================================================================
# Upload-only test files (test_uploads/): drag these onto the dashboard.
# They are NOT in the sample dropdown, so the upload box is the only way in.
# =====================================================================
UP = Path(__file__).parent / "test_uploads"
UP.mkdir(exist_ok=True)


def internal(sender: str, subject: str, date: str) -> EmailMessage:
    """An email written by an employee inside corp.example."""
    msg = base(
        [f"from laptop-42.corp.example ([10.0.8.42]) by mx.corp.example; {date}"],
        "mx.corp.example; spf=pass smtp.mailfrom=corp.example; "
        "dkim=pass header.d=corp.example; dmarc=pass header.from=corp.example",
    )
    msg["From"] = sender
    msg["To"] = "phishing-reports@corp.example"
    msg["Subject"] = subject
    msg["Date"] = date
    return msg


# ------------------------------------------ 05. Pos Laju parcel (direct)
m = base(
    ["from mx.corp.example (mx.corp.example [10.0.0.5]) by mailbox.corp.example; "
     "Thu, 12 Nov 2026 16:40:22 +0800",
     "from relay.p0slaju-track.example (unknown [192.0.2.140]) by mx.corp.example; "
     "Thu, 12 Nov 2026 16:40:19 +0800"],
    "mx.corp.example; spf=pass smtp.mailfrom=p0slaju-track.example; "
    "dkim=pass header.d=p0slaju-track.example; dmarc=none",
)
m["Return-Path"] = "<noreply@p0slaju-track.example>"
m["From"] = '"Pos Laju Malaysia" <noreply@p0slaju-track.example>'
m["To"] = "staff@corp.example"
m["Subject"] = "Bungkusan anda tidak dapat dihantar / Your parcel could not be delivered"
m["Date"] = "Thu, 12 Nov 2026 16:40:15 +0800"
m["Message-ID"] = "<ER4471923MY@p0slaju-track.example>"
m.set_content(
    "Pelanggan yang dihormati,\n\n"
    "Bungkusan ER4471923MY tidak dapat dihantar kerana alamat tidak lengkap. "
    "Sila kemas kini maklumat penghantaran dan bayar caj RM2.90 dalam masa 24 jam, "
    "jika tidak bungkusan akan dipulangkan.\n\n"
    "Dear customer, your parcel ER4471923MY could not be delivered. "
    "Please update your payment details within 24 hours:\n"
    "https://p0slaju-track.example/redeliver?id=ER4471923MY\n\n"
    "Label penghantaran dilampirkan.\n\nPos Laju Malaysia"
)
m.add_alternative(
    "<p>Pelanggan yang dihormati,</p>"
    "<p>Bungkusan <b>ER4471923MY</b> tidak dapat dihantar kerana alamat tidak lengkap. "
    "Sila kemas kini maklumat penghantaran dan bayar caj <b>RM2.90</b> dalam masa 24 jam, "
    "jika tidak bungkusan akan dipulangkan.</p>"
    "<p>Dear customer, your parcel could not be delivered. Please update your payment "
    "details within 24 hours.</p>"
    '<p><a href="https://p0slaju-track.example/redeliver?id=ER4471923MY">Jejak &amp; '
    "jadual semula penghantaran</a></p><p>Label penghantaran dilampirkan.</p>"
    "<p>Pos Laju Malaysia</p>",
    subtype="html",
)
# Harmless placeholder bytes. Real campaigns hide malware in .iso files
# because Windows opens them like a folder.
m.add_attachment(b"PLACEHOLDER - not a real disk image. Safe test data.\n",
                 maintype="application", subtype="octet-stream",
                 filename="Label_Penghantaran_ER4471923MY.iso")
(UP / "05_poslaju_parcel.eml").write_bytes(bytes(m))

# ------------------------- 06. reported with the "Report" button style:
# the phish travels as an ATTACHMENT, and the reporter admits a click.
m = internal('"Farid Hakim" <farid.hakim@corp.example>',
             "FW: URGENT: Your NusaBank account will be suspended within 24 hours",
             "Mon, 9 Nov 2026 09:31:40 +0800")
m.set_content(
    "Hi SOC team,\n\n"
    "Got this one this morning. Sorry - I clicked the link before I noticed the "
    "address was weird, but I closed the page straight away. Saya tak masukkan "
    "apa-apa (I didn't type anything).\n\nFarid\nFinance"
)
m.add_attachment((OUT / "01_obvious_phish.eml").read_bytes(), maintype="message",
                 subtype="rfc822", filename="URGENT NusaBank.eml")
(UP / "06_reported_as_attachment.eml").write_bytes(bytes(m))

# ------------------------- 07. reported with plain "Forward": the phish is
# pasted as text, its real headers are gone. The tool should say so.
original = (OUT / "04_malay_tax_refund.eml").read_bytes()
from email import policy as _policy
from email.parser import BytesParser as _BP
orig = _BP(policy=_policy.default).parsebytes(original)
orig_text = orig.get_body(preferencelist=("plain",)).get_content()
m = internal('"Nurul Aisyah" <nurul.aisyah@corp.example>',
             "Fwd: Notis Bayaran Balik Cukai 2026 - Tindakan Segera Diperlukan",
             "Wed, 11 Nov 2026 08:20:05 +0800")
m.set_content(
    "Is this real? Looks dodgy to me.\n\n"
    "---------- Forwarded message ---------\n"
    f"From: {orig['From']}\n"
    f"Date: {orig['Date']}\n"
    f"Subject: {orig['Subject']}\n"
    "To: <nurul.aisyah@corp.example>\n\n"
    + orig_text
)
(UP / "07_reported_inline_forward.eml").write_bytes(bytes(m))
print(f"Wrote 3 upload test files to {UP}")
