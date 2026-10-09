"""Seed benchmark messages. Brand-parametric: ``{brand}``, ``{domain}`` and
``{brand_lower}`` are filled from the protected set at load time so the same corpus
tests any platform. Hand-written, so each example is one the authors can defend.

Labels: benign, support_impersonation, recruiter_scam, credential_phish, payment_redirect.
Benign examples deliberately share surface cues with attacks (salary figures, links,
deadlines, role words, account language) so that keyword matching alone is penalized.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..intent import Message


@dataclass(frozen=True)
class SeedItem:
    id: str
    label: str
    sender_name: str
    sender_address: str
    subject: str
    body: str
    tags: tuple[str, ...] = ()

    def to_message(self) -> Message:
        return Message(body=self.body, sender_name=self.sender_name,
                       sender_address=self.sender_address, subject=self.subject)


_RAW: list[tuple[str, str, str, str, str, str, tuple[str, ...]]] = [
    # ---------------------------------------------------------------- benign: recruiters
    ("b01", "benign", "Luis Garcia", "luis.garcia@acmerobotics.com", "Summer SWE internship",
     "Hi Priya, I'm a recruiter at Acme Robotics. We're hiring summer software interns in Austin "
     "($42/hour). The posting is at https://acmerobotics.com/careers/1234. If it looks interesting "
     "I'd love to set up a 30-minute intro call next week.", ("salary", "link")),
    ("b02", "benign", "Hannah Kim", "hkim@northwindtraders.com", "Interview scheduling",
     "Thanks for applying to the Analyst role. Could you share your availability for a 45-minute "
     "video interview on Tuesday or Wednesday? The panel will be me and our team lead.", ("interview",)),
    ("b03", "benign", "Granite Analytics Recruiting", "recruiting@graniteanalytics.io", "Application received",
     "We received your application for Data Analyst I. Our team reviews applications within two "
     "weeks and will reach out if there's a match. You can check status any time on {domain}.", ("role_word", "link")),
    ("b04", "benign", "Omar Khan", "omar@cedarlogistics.com", "Quick question about your project",
     "I saw the supply-chain simulation on your profile. We have an operations rotational program "
     "starting in June. Would you be open to a chat? No pressure either way.", ()),
    ("b05", "benign", "Maria Rossi", "maria.rossi@lumenhealth.com", "Offer details",
     "Great news: we'd like to extend an offer for the Clinical Data Coordinator position at "
     "$68,000 base plus benefits. The formal letter will come from our HR system (Workday) and you "
     "can take a week to decide.", ("salary", "role_word")),
    ("b06", "benign", "Ravi Patel", "ravi.patel@bluepeakcapital.com", "Case study deadline",
     "Reminder that the take-home case study is due Friday at 5pm ET. Upload it through the "
     "portal link in your original email. Let me know if you need an extension.", ("urgency", "link_word")),
    ("b07", "benign", "Summit Media Talent", "talent@summitmedia.com", "Career fair follow-up",
     "Nice meeting you at the {brand} virtual career fair. We're hiring a marketing associate; apply "
     "at https://summitmedia.com/jobs and mention my name.", ("brand_mention", "link")),
    ("b08", "benign", "Ethan Wright", "ethan@orbitallabs.io", "Internship: remote option",
     "Following up: the internship can be remote for the first month. Pay is $30/hour, 40 hours a "
     "week, and we provide the laptop. Interviews are on Zoom with two engineers.", ("salary", "remote", "equipment")),
    ("b09", "benign", "Chloe Brown", "cbrown@harborfintech.com", "Background check",
     "As the next step after your offer, our vendor Checkr will email you a link to start the "
     "standard background check. There is no cost to you. Reply if you have questions.", ("background_check", "link_word")),
    ("b10", "benign", "Wei Chen", "wei.chen@pioneerbiotech.com", "Research assistant role",
     "Dr. Novak's lab is looking for a part-time research assistant, 10 hours a week at $22/hour. "
     "Send your CV and a short note on your lab experience by the 15th.", ("salary", "deadline")),
    ("b11", "benign", "Noah Johnson", "noah@ironcladsystems.com", "Re: thanks",
     "You're welcome. I'll pass your resume to the hiring manager for the security analyst role "
     "and circle back by end of next week.", ("role_word",)),
    ("b12", "benign", "Beacon Education", "careers@beaconeducation.org", "Teaching fellowship",
     "Applications for the 2027 teaching fellowship open today. Stipend is $38,000. Details and "
     "FAQ: https://beaconeducation.org/fellowship. Deadline is March 1.", ("salary", "link", "deadline", "today")),
    # ---------------------------------------------------------------- benign: platform support
    ("b13", "benign", "{brand} Support", "support@{domain}", "Re: notification settings",
     "Thanks for reaching out. I've turned off the weekly digest on your account as requested. "
     "Let us know if anything else comes up.", ("support", "account")),
    ("b14", "benign", "{brand} Support", "support@{domain}", "Re: can't upload resume",
     "Sorry about that. PDF uploads over 5 MB fail silently; could you try compressing the file "
     "and uploading again? If it still fails, reply with the file name and we'll look.", ("support",)),
    ("b15", "benign", "{brand}", "no-reply@{domain}", "New message from an employer",
     "You have a new message from Luis Garcia at Acme Robotics. Sign in to {domain} to read and "
     "reply.", ("login_word", "link")),
    ("b16", "benign", "{brand} Trust & Safety", "trust@{domain}", "We removed a job posting you applied to",
     "We removed a posting from 'Quick Pay Remote' after reports it was fraudulent. You don't "
     "need to do anything. If you shared personal information with them, see our safety guide "
     "at https://{domain}/safety.", ("authority", "link", "fraud")),
    ("b17", "benign", "{brand}", "no-reply@{domain}", "Your password was changed",
     "Your {brand} password was changed just now. If this was you, no action is needed. If not, "
     "reset your password from the sign-in page and contact support.", ("password", "security")),
    ("b18", "benign", "{brand} Support", "support@{domain}", "Re: employer verification",
     "The employer account you asked about is verified: they've been on {brand} since 2019 and "
     "have an .edu partnership. Still, never pay a fee or buy equipment for a job.", ("support", "fee_word")),
    # ---------------------------------------------------------------- benign: peers, schools, misc
    ("b19", "benign", "Sofia Diaz", "sdiaz@stanford.edu", "Study group tonight?",
     "A few of us are meeting in the library at 7 to go over the systems problem set. Want to join?", ()),
    ("b20", "benign", "Career Services", "careers@berkeley.edu", "Career fair registration closes tomorrow",
     "Registration for the spring career fair closes tomorrow at noon. Register on {domain} under "
     "Events. Walk-ins will not be admitted this year.", ("role_word", "urgency", "link")),
    ("b21", "benign", "IT Help Desk", "helpdesk@umich.edu", "Scheduled maintenance",
     "Campus single sign-on will be unavailable Saturday 1-3am for maintenance. No action is "
     "required; you may need to sign in again afterward.", ("role_word", "login_word")),
    ("b22", "benign", "Kofi Mensah", "kofi.mensah44@gmail.com", "Referral?",
     "Hey, I saw you interned at Lumen Health last summer. I'm applying for their analyst role; "
     "would you be comfortable referring me or sharing what the interview was like?", ("freemail",)),
    ("b23", "benign", "Financial Aid Office", "finaid@utexas.edu", "FAFSA verification documents",
     "Your file was selected for verification. Upload your signed tax transcript through the "
     "secure student portal by April 30 to avoid a delay in disbursement.", ("verify_word", "deadline", "documents")),
    ("b24", "benign", "Grace Lee", "grace.lee@maplesoftware.com", "Mentorship program",
     "Our alumni mentorship program pairs students with engineers for 6 months. It's free and "
     "remote. Interested? https://maplesoftware.com/mentorship", ("link", "remote")),
    ("b25", "benign", "Prof. Aisha Okafor", "aokafor@gatech.edu", "Letter of recommendation",
     "Happy to write the letter. Send me the job description and your resume, and remind me of "
     "the deadline so I don't miss it.", ("documents", "deadline")),
    ("b26", "benign", "Leo Silva", "leo.silva@crescentfoods.com", "Payroll setup",
     "Welcome aboard! HR will send you a secure link from our payroll provider (ADP) to enter "
     "your direct deposit details after your first day. Never send bank details by email.", ("bank_word", "link_word", "role_word")),
    ("b27", "benign", "Tom Nguyen", "tom@solsticegames.com", "Portfolio feedback",
     "Your level-design portfolio is strong. One suggestion: lead with the puzzle level. We're "
     "not hiring juniors right now but I'll keep you in mind.", ()),
    ("b28", "benign", "Emma Novak", "emma.novak@redwoodinsurance.com", "Offer accepted",
     "Thrilled you accepted! Your start date is June 2. You'll get onboarding paperwork (I-9, W-4) "
     "through our HR portal; bring your ID on day one for the I-9.", ("documents", "role_word")),
    ("b29", "benign", "Sam Khan", "sam.khan@atlasmobility.com", "Declined",
     "After careful consideration we've decided to move forward with other candidates. We "
     "appreciate your time and encourage you to apply for future roles.", ()),
    ("b30", "benign", "Student Affairs", "studentaffairs@asu.edu", "Wellness check-in",
     "Midterms are here. Counseling services offers same-day appointments this week; call "
     "480-555-0100 or book online.", ("phone",)),
    # ---------------------------------------------------------------- support impersonation
    ("s01", "support_impersonation", "{brand} Security Team", "security@{brand_lower}-verify.app", "Unusual sign-in detected",
     "This is the {brand} Security Team. Unusual login activity was detected on your account. "
     "Verify your identity within 24 hours at https://{brand_lower}-verify.app/login or your "
     "account will be suspended.", ()),
    ("s02", "support_impersonation", "{brand} Support", "{brand_lower}.support.team@gmail.com", "Action required: account review",
     "Your account has been flagged for review by our compliance department. To avoid permanent "
     "suspension, confirm your details using the link below today. https://bit.ly/3x{brand_lower}",
     ()),
    ("s03", "support_impersonation", "{brand} Admin", "admin@{domain}.secure-portal.app", "Profile verification",
     "Hello, we are the {brand} admin team. New federal rules require all students to re-verify "
     "their profile. Click here to complete verification immediately: "
     "https://{domain}.secure-portal.app/verify", ()),
    ("s04", "support_impersonation", "Trust & Safety", "trustandsafety@mail-notice.xyz", "Final notice",
     "Final notice from {brand} Trust and Safety: suspicious activity means your messaging "
     "privileges will be removed in 12 hours unless you confirm your account at the link in this "
     "message. http://mail-notice.xyz/{brand_lower}", ()),
    ("s05", "support_impersonation", "{brand} Help Center", "help@{brand_lower}support.co", "We could not deliver your messages",
     "Our systems detected a problem with your inbox. Three employer messages are on hold. Sign in "
     "via https://{brand_lower}support.co/inbox to release them before they expire tonight.", ()),
    ("s06", "support_impersonation", "{brand} Support", "support@{domain}", "Security alert",
     "Dear user, this is an official notification from {brand}. Your account is at risk. Verify "
     "now at http://account-update.net/{brand_lower} or lose access within 24 hours.", ("spoofed_from",)),
    ("s07", "support_impersonation", "{brand} IT Department", "it.department@outlook.com", "Mandatory password update",
     "As part of a security upgrade, all {brand} users must update their password today using "
     "the secure form attached. Failure to comply will result in account deactivation.", ()),
    ("s08", "support_impersonation", "Account Services", "accounts@hr-portal.co", "Your {brand} account",
     "We are the {brand} account services team. A payment to your account failed and your "
     "profile is limited. Update your details here: https://hr-portal.co/{brand_lower}/update", ()),
    ("s09", "support_impersonation", "{brand} Support", "no-reply@{brand_lower}.help", "Ticket #48213 closed",
     "Your support ticket could not be processed because your identity is unconfirmed. Confirm "
     "your identity at https://{brand_lower}.help/confirm within 48 hours to keep your account.", ()),
    ("s10", "support_impersonation", "{brand} Compliance", "compliance-{brand_lower}@proton.me", "Policy violation",
     "Our compliance team has detected a violation of the terms of service on your account. "
     "This is your last chance to appeal: open the attached document and sign in to respond.", ()),
    ("s11", "support_impersonation", "{brand} Security", "security@{domain}", "Login from new device",
     "We noticed a login from a new device in another country. If this wasn't you, secure your "
     "account immediately at https://{domain}.auth-check.top. This link expires in 1 hour.", ("spoofed_from",)),
    ("s12", "support_impersonation", "{brand} Team", "team@{brand_lower}-official.com", "Important: verify to keep your profile visible",
     "Employers can no longer see your profile until you verify it. Verification takes 30 "
     "seconds: https://{brand_lower}-official.com/verify. Do it today so you don't miss offers.", ()),
    ("s13", "support_impersonation", "Verification Team", "verify@docs-share.site", "Document check",
     "{brand} requires a copy of your student ID and driver's license to confirm your identity "
     "after unusual activity. Upload them at https://docs-share.site/{brand_lower} right away.", ()),
    ("s14", "support_impersonation", "{brand} Support", "{brand_lower}-support@yahoo.com", "Re: your message",
     "Hi, {brand} support here. We saw your complaint. To process it we need you to confirm your "
     "login and the one-time code we just texted you. Reply with both and we'll fix it now.", ()),
    # ---------------------------------------------------------------- recruiter scams
    ("r01", "recruiter_scam", "Acme HR", "acme.hr.team@gmail.com", "You're hired",
     "Congratulations, you have been selected for a remote Data Entry Assistant position paying "
     "$45/hour, no interview needed. To continue, add our hiring manager on Telegram @acme_hr and "
     "we will send the onboarding packet.", ()),
    ("r02", "recruiter_scam", "Jane Doe", "jane.doe.recruit@outlook.com", "Personal assistant opportunity",
     "I'm looking for a reliable student to work as my personal assistant, 10 hours a week, "
     "$800 weekly. The work is simple: receiving packages and running errands. Text me at "
     "+1 (404) 555-0199 to start this week.", ()),
    ("r03", "recruiter_scam", "Lumen Health Careers", "lumenhealth.careers@gmail.com", "Interview via Google Chat",
     "Your resume was shortlisted for the Remote Customer Support role ($38/hr). The interview "
     "will be conducted over Google Chat with the hiring manager. Add briefing.manager@gmail.com "
     "and send the code LH-2291 to begin.", ()),
    ("r04", "recruiter_scam", "Hiring Manager", "hr@talent-connect.online", "Equipment for your home office",
     "Welcome to the team! Before training, you will purchase the laptop and software from our "
     "approved vendor. We will mail you a check for $3,450 to cover it; deposit the check and "
     "send the vendor payment via Zelle.", ()),
    ("r05", "recruiter_scam", "Priya Patel", "priya.p.recruiting@proton.me", "Confidential role",
     "I'm a senior recruiter working with a Fortune 500 client. The role pays $95k with no "
     "experience required but is confidential; please do not discuss it with your school. Send "
     "your full name, date of birth and home address to start the background check.", ()),
    ("r06", "recruiter_scam", "Northwind Traders", "northwindtraders.jobs@yahoo.com", "Job offer - start immediately",
     "We reviewed your {brand} profile and you are hired as a remote Payroll Clerk. Start "
     "immediately. A $150 registration fee is required for your training materials; pay via "
     "Cash App and send the receipt.", ()),
    ("r07", "recruiter_scam", "Talent Acquisition", "talent@orbitallabs.co", "Mystery shopper program",
     "Earn up to $500 per assignment as a mystery shopper, flexible hours, work from home. We "
     "send you funds, you buy gift cards at the assigned store and report the codes to us.", ()),
    ("r08", "recruiter_scam", "Dr. Michael Stone", "m.stone.lab@gmail.com", "Research assistant (remote)",
     "I am a professor at your university looking for a remote research assistant at $400/week. "
     "You will be paid in advance by check. Reply with your personal email so we can continue "
     "the conversation over text.", ()),
    ("r09", "recruiter_scam", "Harbor Fintech HR", "harborfintech-hr@mail.com", "Final step: identity check",
     "You passed the chat interview. For the final step, upload a photo of your passport or "
     "driver's license and your bank login so payroll can be set up before Friday.", ()),
    ("r10", "recruiter_scam", "Quick Pay Remote", "jobs@quickpayremote.xyz", "Immediate hire: $35/hr",
     "Immediate hire for online survey assistants, $35/hr, flexible hours, no experience. "
     "Continue your application on WhatsApp: +1 213 555 0142. Positions fill fast, apply today.", ()),
    ("r11", "recruiter_scam", "Sam Lee", "sam.lee@cedarlogistics-careers.com", "Offer letter attached",
     "Please find your offer letter attached. To activate your employee account, pay the $89 "
     "onboarding fee through the link in the document. This is refunded in your first paycheck.", ()),
    ("r12", "recruiter_scam", "Ember Studio Recruiting", "recruiting@emberstudio.co", "Hiring now",
     "We are hiring! Skip the interview and start earning $1,200 a week from home as a brand "
     "ambassador. Reply with your Telegram handle and we'll send the contract today.", ()),
    ("r13", "recruiter_scam", "Hannah Kim", "hkim.northwind@gmail.com", "Re: Analyst role (urgent)",
     "Following up on the Analyst role. The hiring manager wants to move fast, so let's continue "
     "on Signal. Also, we need your SSN for the offer letter before end of day.", ()),
    ("r14", "recruiter_scam", "Campus Rep Program", "campusrep@summit-media-jobs.com", "Paid campus rep",
     "Be our paid campus representative: $600/week for posting flyers. First, buy the starter "
     "kit ($120) from our supplier; we reimburse it with your first check. Reply YES to begin.", ()),
    # ---------------------------------------------------------------- credential phishing
    ("c01", "credential_phish", "IT Help Desk", "helpdesk@mail-notice.xyz", "Password expiring",
     "Your password expires today. Enter your current password and the verification code we "
     "sent to confirm your account: http://bit.ly/x1pw", ()),
    ("c02", "credential_phish", "{brand}", "no-reply@{brand_lower}.co", "Confirm your email",
     "We need to confirm your email. Sign in here with your {brand} password to continue "
     "receiving employer messages: https://{brand_lower}.co/confirm", ()),
    ("c03", "credential_phish", "Microsoft 365", "office365@secure-portal.app", "Shared document",
     "Luis Garcia shared 'Offer_Letter.pdf' with you. Open the document and sign in with your "
     "university credentials to view it: https://secure-portal.app/view/8821", ()),
    ("c04", "credential_phish", "{brand} Support", "support@{domain}", "One-time code",
     "To finish verifying your account, reply with the 6-digit verification code we just sent "
     "to your phone. This code expires in 10 minutes.", ("spoofed_from",)),
    ("c05", "credential_phish", "Campus Portal", "portal@auth-check.top", "Re-authenticate",
     "Your session has expired. Re-enter your credentials at https://auth-check.top/sso to "
     "avoid losing your saved applications.", ()),
    ("c06", "credential_phish", "Payroll", "payroll@hr-portal.co", "Direct deposit update",
     "Your direct deposit was rejected. Log in using your employee ID and password at "
     "https://hr-portal.co/login to update your bank information before the payroll cutoff.", ()),
    ("c07", "credential_phish", "Ethan Wright", "ethan.wright@orbitallabs.io", "Interview link",
     "Here is your interview link: https://orbitallabs.io.docs-share.site/meet. Sign in with "
     "your {brand} account to join.", ("hard",)),
    ("c08", "credential_phish", "{brand} Security", "security@xn--hndshake-9zf.com", "Verify",
     "Multiple failed logins were detected. Verify your identity by entering your password and "
     "date of birth at https://xn--hndshake-9zf.com/verify.", ("punycode",)),
    ("c09", "credential_phish", "Google", "accounts-noreply@account-update.net", "Account recovery",
     "A recovery request was started for your Google account. If this was not you, enter your "
     "password here to cancel it: https://account-update.net/recover", ()),
    ("c10", "credential_phish", "Financial Aid", "finaid@secure-portal.app", "Disbursement on hold",
     "Your financial aid disbursement is on hold. Validate your login and social security "
     "number at https://secure-portal.app/aid within 48 hours to release funds.", ()),
    # ---------------------------------------------------------------- payment redirect
    ("p01", "payment_redirect", "Payroll", "payroll@talent-connect.online", "Training fee",
     "Per the hiring manager, deposit the check we mailed and send back $900 via Zelle for your "
     "training fee before your start date.", ()),
    ("p02", "payment_redirect", "Maria Rossi", "maria.rossi.lumen@gmail.com", "Urgent favor",
     "I'm in a meeting and can't talk. I need you to buy three $100 Apple gift cards for a "
     "client and send me the codes. I'll reimburse you today.", ()),
    ("p03", "payment_redirect", "Accounts Payable", "ap@northwindtraders.co", "Updated banking details",
     "Our bank account has changed. Please send this month's stipend payment to the new routing "
     "and account number in the attached PDF.", ()),
    ("p04", "payment_redirect", "{brand} Billing", "billing@{brand_lower}-alerts.com", "Overdue balance",
     "Your {brand} premium subscription payment failed. Pay the $49 balance by Bitcoin or "
     "PayPal within 24 hours to avoid account suspension: https://{brand_lower}-alerts.com/pay", ()),
    ("p05", "payment_redirect", "Hiring Manager", "manager@quickpayremote.xyz", "Overpayment",
     "We accidentally overpaid your first check by $1,200. Please wire the difference back "
     "today to the account below so payroll can be corrected.", ()),
    ("p06", "payment_redirect", "Student Housing", "housing@docs-share.site", "Deposit required",
     "Your housing spot is reserved. Send the $500 deposit via Venmo to @campus-housing-2027 "
     "within 24 hours or it will be released.", ()),
    ("p07", "payment_redirect", "Visa Services", "visa.services@mail.com", "Work authorization fee",
     "To process your work authorization for the job you accepted, a $275 processing fee must "
     "be paid by gift card. Send the card numbers to this address.", ()),
    ("p08", "payment_redirect", "Tom Nguyen", "tom.nguyen.solstice@outlook.com", "Refund",
     "We refunded you $2,000 instead of $200 for the equipment. Keep $200 and send $1,800 back "
     "by Cash App today, otherwise the hiring manager said your position will be terminated.", ()),
]


def load_seed(protected: list[str]) -> list[SeedItem]:
    """Instantiate the corpus for a protected set (first domain and brand token are used)."""
    from ..domains import brand_tokens, protected_domains
    doms = sorted(protected_domains(protected))
    brands = sorted(brand_tokens(protected))
    if not doms or not brands:
        raise ValueError("protected set needs a domain and a brand name")
    domain = doms[0]
    brand_lower = next((b for b in brands if b == domain.split(".")[0]), brands[0])
    brand = next((p for p in protected if p.casefold() == brand_lower), brand_lower.title())
    fmt = {"brand": brand, "domain": domain, "brand_lower": brand_lower}
    out: list[SeedItem] = []
    for sid, label, name, addr, subj, body, tags in _RAW:
        out.append(SeedItem(sid, label, name.format(**fmt), addr.format(**fmt),
                            subj.format(**fmt), body.format(**fmt), tags))
    return out
