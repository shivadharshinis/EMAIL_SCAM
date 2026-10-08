# Phase 3 dataset

`email_dataset.csv` is a small, local teaching/demo dataset created for this
student project. It contains anonymized, synthetic examples with the columns
`subject`, `text`, and `label`, where `0` means legitimate/ham and `1` means
phishing.

## Origin and usage basis

No suitable existing public dataset with clear, project-compatible usage terms
was available in this repository, and no external dataset was downloaded.
The examples were written locally for reproducible development and are
appropriate for this repository's educational demo only.

## Size and labels

The dataset contains 20 examples: 10 legitimate and 10 phishing. Labels are
assigned from the intended message scenario. The messages use example domains,
anonymized identities, and non-routable/example URLs.

## Limitations

This is not a production-grade corpus. It is small, balanced by construction,
synthetic, and likely biased toward obvious wording. It does not represent
real-world language diversity, mail-client formatting, multilingual content,
class imbalance, adversarial evasion, or the prevalence of legitimate and
phishing mail in production. A small test split also makes metrics unstable.
The model must not be used as the sole basis for blocking or investigating
messages.

The training process uses a fixed `random_state=42`, a simple stratified
train/test split, and default TF-IDF and Logistic Regression settings. No
hyperparameter search or metric-driven tuning is performed.

## Real-corpus preparation

`prepare_dataset.py` is a passive, offline preparation tool. It reads approved
source CSV files from `raw/`, writes cleaned data to `derived/`, and writes
machine-readable and human-readable audit reports to `reports/`.

The current preparation sources are:

- Nazario phishing rows from the CC BY 4.0 Zenodo curated record
  (`Nazario.csv` and `Nazario_5.csv`), compared and deduplicated rather than
  blindly combined.
- The University of Twente phishing validation dataset
  (CC BY 4.0, DOI `10.5281/zenodo.13474746`). Its safe and phishing labels are
  inspected, and retained Twente rows are reserved deterministically when
  possible.
- Explicitly legitimate/ham rows from Enron and SpamAssassin. SpamAssassin
  spam is excluded and is never relabeled as phishing. Nigerian Fraud is not
  used.

The resulting schema is `subject,text,label,source`, with `0` meaning
legitimate and `1` meaning phishing. Empty records and exact duplicate
subject/body or body content are removed before any future train/test split.
Potential near-duplicate campaign/template groups are reported but not
silently deleted. Sampling of excess legitimate records uses seed `42`.

Run preparation only (this does not train the model):

```powershell
cd backend
.\.venv\Scripts\python.exe -m app.engines.ml.data.prepare_dataset
```

The downloaded `raw/` files, derived corpora, and reports are intentionally
ignored by Git. `sources.json` records provenance, labels, attribution, access
date, and known limitations. Enron content may contain personal or confidential
information and should not be redistributed unnecessarily. A 10,000-row
corpus, even if reached, remains a student/research prototype and does not
represent all real-world email traffic.

URLs in source messages are preserved as text only. The preparation code never
opens URLs, resolves domains, probes IPs, executes or unpacks attachments, or
sends email.
