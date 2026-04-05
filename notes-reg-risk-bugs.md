# Registration Risk Assessment Bugs (from screenshot)

## Issues identified:

1. **Bullet character**: Using Unicode \u26A0 (warning sign) which renders as `&` in the PDF — jsPDF doesn't support this Unicode character
2. **Font**: Using helvetica 'normal' but the screenshot shows monospace/courier rendering — likely jsPDF fallback for unsupported characters
3. **False positive - Transfer lock**: Status codes show "client transfer prohibited" but risk says "not set". The status string matching uses `s.toLowerCase().includes('clienttransferprohibited')` — but the actual status strings have SPACES: "client transfer prohibited" not "clienttransferprohibited". The includes check fails because the status has spaces.
4. **False positive - Delete lock**: Same issue — "client delete prohibited" has spaces but the check looks for "clientdeleteprohibited" without spaces.
5. **No evidence**: Risk statements don't cite the actual data from the RDAP table

## Root cause for false positives:
The RDAP status codes come in human-readable format with spaces ("client transfer prohibited") but the code checks for the EPP status code format without spaces ("clienttransferprohibited"). Need to normalize by removing spaces before comparison.

## Fix plan:
- Normalize status string comparison (strip spaces)
- Replace Unicode warning sign with simple text bullet or dash
- Use proper font settings
- Add evidence citations referencing actual RDAP data values
- Also show "all clear" items when locks ARE present
