# SquatDetect — Domain Impersonation Detection Tool

SquatDetect is a cybersecurity project designed to identify potential domain impersonation by generating lookalike domains and analyzing their DNS records and risk scores.

## Architecture

- **Backend:** Python and FastAPI
- **Frontend:** HTML, CSS, and JavaScript
- **Detection:** Domain permutation and DNS analysis
- **Risk Analysis:** Risk scoring and threat classification

## How It Works

1. **Domain Permutation:** Generates variations using techniques such as typosquatting, homoglyphs, and combosquatting.
2. **DNS Detection:** Checks domain availability and DNS records, including A, AAAA, and MX records.
3. **Risk Scoring:** Assigns risk scores based on DNS results and attack characteristics.
4. **Dashboard:** Displays scan results for analysis.

## Technologies Used

- Python
- FastAPI
- HTML, CSS, JavaScript
- DNS resolution
- Git and GitHub

## Project Objective

To help identify suspicious lookalike domains that could be used for phishing or brand impersonation.

## Future Enhancements

- Integration with threat intelligence APIs
- WHOIS registration information
- Exportable scan reports
- Improved domain risk analysis
