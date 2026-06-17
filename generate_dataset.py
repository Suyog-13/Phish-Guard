"""
generate_dataset.py
--------------------
Builds a labeled dataset of URLs for training, entirely offline.

Why synthetic data? This project runs in a sandboxed environment with no
internet access, so it can't download a live phishing feed (e.g. PhishTank,
OpenPhish) or a Kaggle CSV at build time. Instead, this script programmatically
generates two classes of URL using patterns that are well documented in
phishing research:

  - LEGITIMATE: short, clean domains, real-looking brand/word combos,
    https, few or no query tricks.
  - PHISHING:   the classic lexical tricks — raw IPs, lookalike/hyphenated
    subdomains, suspicious keywords, link shorteners, abused free TLDs,
    '@' tricks, long noisy paths.

Each run also adds randomness/overlap so the classes aren't perfectly
separable (real traffic isn't either), which keeps the trained model honest.

>>> To use a REAL dataset instead <<<
If you want to train on a real labelled dataset (recommended for anything
beyond a portfolio demo), download one such as:
  - PhishTank: https://phishtank.org/developer_info.php
  - UCI Phishing Websites dataset: https://archive.ics.uci.edu/dataset/327
and save it as a CSV with two columns: url,label (label = 1 for phishing,
0 for legitimate). Then run:
    python train_model.py --csv path/to/your_dataset.csv
"""

import csv
import random
import string

random.seed(42)

LEGIT_BRANDS = [
    "github", "wikipedia", "openai", "nytimes", "stackoverflow", "spotify",
    "dropbox", "notion", "figma", "airbnb", "coursera", "khanacademy",
    "mozilla", "python", "kernel", "gnu", "wordpress", "cloudflare",
    "redhat", "atlassian", "shopify", "stripe", "trello", "zoom",
]
LEGIT_TLDS = ["com", "org", "net", "io", "dev", "co"]
LEGIT_PATHS = [
    "", "about", "blog", "docs", "pricing", "careers", "help",
    "products/overview", "articles/2025/security", "user/settings",
    "search?q=python", "download", "contact",
]

BRAND_LOOKALIKES = [
    "paypal", "ebay", "amazon", "apple", "netflix", "microsoft", "bankofamerica",
    "wellsfargo", "chase", "facebook", "instagram", "dhl", "fedex", "irs",
]
PHISHY_WORDS = [
    "login", "verify", "secure", "account", "update", "confirm", "signin",
    "password", "recover", "unlock", "suspend", "billing", "wallet",
]
PHISHY_TLDS = ["tk", "ml", "ga", "cf", "gq", "xyz", "top", "club", "work", "click", "loan", "win"]
SHORTENERS = ["bit.ly", "tinyurl.com", "goo.gl", "is.gd", "buff.ly", "cutt.ly"]


def _rand_token(n=6):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def make_legit_url():
    brand = random.choice(LEGIT_BRANDS)
    tld = random.choice(LEGIT_TLDS)
    path = random.choice(LEGIT_PATHS)
    scheme = "https"  # legit sample is mostly https, with occasional plain http
    if random.random() < 0.08:
        scheme = "http"
    sub = ""
    if random.random() < 0.25:
        sub = random.choice(["www.", "docs.", "blog.", "app."])
    url = f"{scheme}://{sub}{brand}.{tld}/{path}".rstrip("/")

    # ~12% of legit URLs get a "hard" twist that overlaps with phishing-style
    # patterns (real sites do use hyphens, account/login paths, redirects).
    # This keeps the two classes from being perfectly separable.
    if random.random() < 0.12:
        twist = random.random()
        if twist < 0.3:
            url = url.replace(f"{brand}.", f"{brand}-app.")
        elif twist < 0.6:
            url = url.rstrip("/") + "/account/login?redirect=1"
        else:
            url += f"?ref={_rand_token(6)}"
    return url


def make_phishing_url():
    style = random.random()

    if style < 0.18:
        # raw IP host
        ip = ".".join(str(random.randint(1, 255)) for _ in range(4))
        path = random.choice(PHISHY_WORDS) + "/" + _rand_token(5)
        return f"http://{ip}/{path}"

    if style < 0.36:
        # brand impersonation with hyphenated, multi-subdomain host
        brand = random.choice(BRAND_LOOKALIKES)
        word = random.choice(PHISHY_WORDS)
        tld = random.choice(PHISHY_TLDS)
        sub_count = random.choice([2, 3])
        subs = ".".join(_rand_token(5) for _ in range(sub_count - 1))
        return f"http://{brand}-{word}.{subs}.{tld}/account/{_rand_token(6)}"

    if style < 0.55:
        # '@' trick — text before @ looks like the real domain
        brand = random.choice(BRAND_LOOKALIKES)
        real_host = _rand_token(8) + "." + random.choice(PHISHY_TLDS)
        return f"http://{brand}.com@{real_host}/{random.choice(PHISHY_WORDS)}"

    if style < 0.72:
        # link shortener
        short = random.choice(SHORTENERS)
        return f"https://{short}/{_rand_token(7)}"

    if style < 0.88:
        # long noisy query string + suspicious words + https token decoy
        brand = random.choice(BRAND_LOOKALIKES)
        words = "-".join(random.sample(PHISHY_WORDS, k=2))
        tld = random.choice(PHISHY_TLDS)
        return (f"http://secure-{brand}-{words}.{_rand_token(4)}.{tld}/"
                f"https/{_rand_token(5)}?session={_rand_token(10)}&redirect=1")

    if style < 0.95:
        # generic hyphen-heavy free-tld phishing page
        word = random.choice(PHISHY_WORDS)
        tld = random.choice(PHISHY_TLDS)
        return f"http://{word}-update-{_rand_token(5)}.{tld}/{_rand_token(6)}"

    # "stealthy" phishing: clean https, short host, common tld, no obvious
    # keyword — a typosquat that relies on the name alone, not lexical tricks.
    # These are intentionally hard for a lexical-only model to catch, which
    # keeps the dataset (and the resulting accuracy) realistic.
    brand = random.choice(BRAND_LOOKALIKES)
    decoy = random.choice(["", "online", "secure" + str(random.randint(1, 9))])
    return f"https://{brand}{decoy}.{random.choice(LEGIT_TLDS)}/{_rand_token(4)}"


def build_dataset(n_per_class=2500, label_noise=0.03):
    rows = []
    for _ in range(n_per_class):
        rows.append((make_legit_url(), 0))
    for _ in range(n_per_class):
        rows.append((make_phishing_url(), 1))
    random.shuffle(rows)

    # Flip a small fraction of labels to simulate real-world annotation
    # noise (mislabeled training data is normal, not a bug).
    if label_noise > 0:
        n_flip = int(len(rows) * label_noise)
        idxs = random.sample(range(len(rows)), n_flip)
        for i in idxs:
            url, label = rows[i]
            rows[i] = (url, 1 - label)

    return rows


if __name__ == "__main__":
    rows = build_dataset(n_per_class=2500)
    out_path = "dataset/urls_dataset.csv"
    with open(out_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "label"])
        writer.writerows(rows)
    legit_n = sum(1 for _, label in rows if label == 0)
    phish_n = sum(1 for _, label in rows if label == 1)
    print(f"Wrote {len(rows)} rows to {out_path}  (legit={legit_n}, phishing={phish_n})")
