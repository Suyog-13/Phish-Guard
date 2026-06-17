(() => {
  const form = document.getElementById('scan-form');
  const input = document.getElementById('url-input');
  const scanBtn = document.getElementById('scan-btn');
  const scanLog = document.getElementById('scan-log');
  const result = document.getElementById('result');
  const errorBanner = document.getElementById('error-banner');
  const gaugeFill = document.getElementById('gauge-fill');
  const gaugeScore = document.getElementById('gauge-score');
  const verdictTag = document.getElementById('verdict-tag');
  const verdictUrl = document.getElementById('verdict-url');
  const verdictSub = document.getElementById('verdict-sub');
  const checksGrid = document.getElementById('checks-grid');

  const GAUGE_CIRCUMFERENCE = 2 * Math.PI * 68; // r=68, matches the SVG circle

  const VERDICT_META = {
    safe: { label: 'SAFE', color: 'var(--signal-green)', sub: 'No major phishing indicators detected.' },
    suspicious: { label: 'SUSPICIOUS', color: 'var(--warn-amber)', sub: 'Some red flags found — proceed carefully.' },
    phishing: { label: 'LIKELY PHISHING', color: 'var(--threat-red)', sub: 'Multiple strong phishing indicators detected.' },
  };

  document.querySelectorAll('.example-chip').forEach((chip) => {
    chip.addEventListener('click', () => {
      input.value = chip.dataset.url;
      form.requestSubmit();
    });
  });

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const url = input.value.trim();
    hideError();
    if (!url) {
      showError('Enter a URL first — try one of the examples above.');
      return;
    }

    setLoading(true);
    result.style.display = 'none';
    scanLog.style.display = 'block';
    scanLog.innerHTML = '';

    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
      });
      const data = await res.json();

      if (!res.ok) {
        showError(data.error || 'Something went wrong scanning that URL.');
        scanLog.style.display = 'none';
        setLoading(false);
        return;
      }

      await playScanLog(data.checks);
      renderResult(data);
    } catch (err) {
      showError('Could not reach the scanning service. Is the Flask server running?');
      scanLog.style.display = 'none';
    } finally {
      setLoading(false);
    }
  });

  function setLoading(isLoading) {
    scanBtn.disabled = isLoading;
    scanBtn.textContent = isLoading ? 'Scanning…' : 'Scan URL';
  }

  function showError(msg) {
    errorBanner.textContent = msg;
    errorBanner.style.display = 'block';
  }
  function hideError() {
    errorBanner.style.display = 'none';
  }

  function playScanLog(checks) {
    return new Promise((resolve) => {
      const lines = [
        `> resolving structure of target URL...`,
        `> extracting lexical features...`,
      ];
      checks.forEach((c) => {
        const tag = c.flag ? `[FLAG]` : `[clear]`;
        lines.push(`> ${c.label}: ${c.value}  ${tag}`);
      });
      lines.push(`> running classifier...`);

      let i = 0;
      const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
      const delay = reduceMotion ? 0 : 90;

      function next() {
        if (i >= lines.length) {
          resolve();
          return;
        }
        const div = document.createElement('div');
        div.className = 'log-line';
        const text = lines[i];
        if (text.includes('[FLAG]')) {
          div.innerHTML = text.replace('[FLAG]', '<span class="flag-hit">[FLAG]</span>');
        } else if (text.includes('[clear]')) {
          div.innerHTML = text.replace('[clear]', '<span class="flag-clear">[clear]</span>');
        } else {
          div.textContent = text;
        }
        scanLog.appendChild(div);
        scanLog.scrollTop = scanLog.scrollHeight;
        i += 1;
        setTimeout(next, delay);
      }
      next();
    });
  }

  function renderResult(data) {
    const meta = VERDICT_META[data.verdict] || VERDICT_META.suspicious;

    verdictTag.textContent = meta.label;
    verdictTag.className = `verdict-tag ${data.verdict}`;
    verdictUrl.textContent = data.url;
    verdictSub.textContent = `${meta.sub} Model confidence: ${(data.model_probability_phishing * 100).toFixed(1)}% probability of phishing.`;

    gaugeScore.textContent = data.risk_score;
    gaugeScore.style.color = meta.color;

    const offset = GAUGE_CIRCUMFERENCE * (1 - data.risk_score / 100);
    gaugeFill.style.stroke = meta.color;
    // force reflow so the transition replays on repeated scans
    gaugeFill.style.transition = 'none';
    gaugeFill.style.strokeDashoffset = GAUGE_CIRCUMFERENCE;
    void gaugeFill.offsetWidth;
    gaugeFill.style.transition = '';
    requestAnimationFrame(() => {
      gaugeFill.style.strokeDashoffset = offset;
    });

    checksGrid.innerHTML = '';
    data.checks.forEach((c) => {
      const item = document.createElement('div');
      item.className = 'check-item';
      const iconClass = c.flag ? `flag-${c.severity}` : 'clear';
      item.innerHTML = `
        <span class="check-icon ${iconClass}">${c.flag ? flagIcon() : checkIcon()}</span>
        <div>
          <p class="check-label">${escapeHtml(c.label)}</p>
          <p class="check-value">${escapeHtml(String(c.value))}</p>
        </div>`;
      checksGrid.appendChild(item);
    });

    result.style.display = 'block';
    result.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  function checkIcon() {
    return `<svg width="16" height="16" viewBox="0 0 24 24" fill="none"><path d="M5 12.5L9.5 17L19 7" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/></svg>`;
  }
  function flagIcon() {
    return `<svg width="16" height="16" viewBox="0 0 24 24" fill="none"><path d="M12 9v4M12 16.5h.01M10.3 4.3a2 2 0 0 1 3.4 0l8 13.86A2 2 0 0 1 20 21H4a2 2 0 0 1-1.7-2.84l8-13.86z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>`;
  }
  function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }
})();
