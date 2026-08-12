# Sanitized synthetic samples

These `.eml` files are safe, generated examples that use reserved domains,
placeholder identities, and inert attachment content. They are provided for
manual testing of sanitization-shaped input.

They are **not** sanitized copies of real SOC emails and must not be used to
claim production accuracy. Real organizational samples still require an
authorized collection, privacy review, and separate validation labels.

Run them offline from the repository root:

```powershell
python main.py -F samples\sanitized --no-banner
```

Contents:

- `sanitized_benign.eml` — ordinary business message
- `sanitized_phishing.eml` — Reply-To mismatch, failed authentication, and a typosquat URL
- `sanitized_html_mismatch.eml` — displayed-link versus destination mismatch
- `sanitized_attachment.eml` — inert attachment with a deceptive double extension
