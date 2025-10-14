const $ = (selector, scope = document) => scope.querySelector(selector);
const $$ = (selector, scope = document) => Array.from(scope.querySelectorAll(selector));

const formatter = new Intl.DateTimeFormat(undefined, {
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
});

function updateThresholdDisplay(range, output) {
  output.textContent = Number(range.value).toFixed(2);
}

function toggleMode(mode) {
  $$('.field[data-field]').forEach((field) => {
    const isActive = field.dataset.field === mode;
    field.classList.toggle('hidden', !isActive);
  });
}

function setStatus(label, { busy = false, tone = 'neutral' } = {}) {
  const statusLabel = $('.status__label');
  const pulse = $('.status__pulse');
  statusLabel.textContent = label;
  statusLabel.dataset.tone = tone;
  if (busy) {
    pulse.hidden = false;
  } else {
    pulse.hidden = true;
  }
}

function addLogEntry({ request, response, success }) {
  const log = $('#event-log');
  const entry = document.createElement('li');
  entry.className = 'log__entry';

  const time = document.createElement('time');
  time.dateTime = new Date().toISOString();
  time.textContent = `${success ? '✔' : '✖'} ${formatter.format(new Date())}`;

  const requestBlock = document.createElement('pre');
  requestBlock.textContent = `REQUEST\n${request}`;

  const responseBlock = document.createElement('pre');
  responseBlock.textContent = `RESPONSE\n${response}`;

  entry.append(time, requestBlock, responseBlock);
  log.prepend(entry);
}

function renderResultCard(data) {
  const results = $('#results');
  if (!results) return;
  const placeholder = $('.results__placeholder', results);
  if (placeholder) {
    placeholder.remove();
  }

  const card = document.createElement('article');
  card.className = 'result-card';

  const header = document.createElement('div');
  header.className = 'result-card__header';

  const verdict = document.createElement('span');
  verdict.className = 'result-card__verdict';
  const verdictText = String(data.verdict ?? '').trim();
  const malicious = /恶/.test(verdictText) || /mal/i.test(verdictText);
  verdict.dataset.state = malicious ? 'malicious' : 'benign';
  verdict.textContent = malicious ? 'MALICIOUS' : 'BENIGN';

  const score = document.createElement('span');
  score.className = 'result-card__score';
  const probability = Number(data.probability ?? 0);
  const displayProbability = data.display_probability ?? `${(probability * 100).toFixed(2)}%`;
  score.textContent = `Confidence: ${displayProbability}`;

  header.append(verdict, score);

  const meta = document.createElement('div');
  meta.className = 'result-card__meta';
  meta.innerHTML = `
    <p><strong>File:</strong> ${data.file_path ?? 'Unknown'}</p>
    <p><strong>Model:</strong> ${data.model_path ?? 'Default'}</p>
    <p><strong>Threshold:</strong> ${(Number(data.threshold ?? 0).toFixed(2))}</p>
  `;

  const json = document.createElement('pre');
  json.className = 'result-card__json';
  json.textContent = JSON.stringify(data, null, 2);

  card.append(header, meta, json);
  results.prepend(card);
}

function serialiseForm({ mode, threshold, modelPath, file, pathValue }) {
  const cleanedThreshold = threshold ? Number(threshold).toFixed(2) : undefined;
  if (mode === 'upload') {
    if (!file) {
      throw new Error('请选择需要扫描的文件。');
    }
    const formData = new FormData();
    formData.append('file', file);
    if (cleanedThreshold) {
      formData.append('threshold', cleanedThreshold);
    }
    if (modelPath) {
      formData.append('model_path', modelPath);
    }
    return { body: formData, headers: undefined };
  }

  if (!pathValue) {
    throw new Error("请输入服务器上的文件路径。");
  }

  const payload = { path: pathValue };
  if (cleanedThreshold) {
    payload.threshold = Number(cleanedThreshold);
  }
  if (modelPath) {
    payload.model_path = modelPath;
  }
  return {
    body: JSON.stringify(payload),
    headers: { 'Content-Type': 'application/json' },
  };
}

function bindScrollButtons() {
  $$('[data-scroll-target]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const target = document.querySelector(btn.dataset.scrollTarget ?? '');
      if (target) {
        target.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    });
  });
}

document.addEventListener('DOMContentLoaded', () => {
  const form = $('#analysis-form');
  const thresholdRange = $('#threshold');
  const thresholdOutput = $('#threshold-value');
  const hero = $('.hero');

  if (thresholdRange && thresholdOutput) {
    updateThresholdDisplay(thresholdRange, thresholdOutput);
    thresholdRange.addEventListener('input', () => updateThresholdDisplay(thresholdRange, thresholdOutput));
  }

  $$('input[name="mode"]').forEach((radio) => {
    radio.addEventListener('change', (event) => {
      toggleMode(event.target.value);
    });
  });

  toggleMode('upload');
  bindScrollButtons();

  form?.addEventListener('submit', async (event) => {
    event.preventDefault();
    const submitButton = $('button[type="submit"]', form);
    submitButton.disabled = true;

    const mode = ($$('input[name="mode"]').find((input) => input.checked) ?? { value: 'upload' }).value;
    const fileInput = $('#file');
    const file = fileInput?.files?.[0];
    const pathValue = $('#path')?.value.trim();
    const threshold = thresholdRange?.value;
    const modelPath = $('#model_path')?.value.trim();

    let requestDescription = '';
    let body;
    let headers;

    try {
      ({ body, headers } = serialiseForm({ mode, threshold, modelPath, file, pathValue }));
      requestDescription = mode === 'upload'
        ? `POST /predict (multipart)\nthreshold=${threshold}\nmodel=${modelPath || 'default'}\nfile=${file?.name ?? 'n/a'}`
        : `POST /predict (json)\nthreshold=${threshold}\nmodel=${modelPath || 'default'}\npath=${pathValue}`;
    } catch (error) {
      setStatus(error.message, { busy: false, tone: 'error' });
      submitButton.disabled = false;
      return;
    }

    setStatus('Transmitting payload to sentinel...', { busy: true });

    try {
      const response = await fetch('/predict', {
        method: 'POST',
        body,
        headers,
      });
      const text = await response.text();
      let payload;
      try {
        payload = JSON.parse(text);
      } catch (parseError) {
        throw new Error('无法解析服务响应，请检查服务器日志。');
      }

      if (!response.ok) {
        const message = payload?.error || `服务返回错误 (${response.status})`;
        setStatus(message, { busy: false, tone: 'error' });
        addLogEntry({ request: requestDescription, response: text, success: false });
        return;
      }

      renderResultCard(payload);
      setStatus('Scan complete. Sentinel standing by.', { busy: false, tone: 'success' });
      addLogEntry({ request: requestDescription, response: JSON.stringify(payload, null, 2), success: true });
    } catch (networkError) {
      setStatus(networkError.message || '网络异常，扫描失败。', { busy: false, tone: 'error' });
      addLogEntry({
        request: requestDescription,
        response: networkError.message || String(networkError),
        success: false,
      });
    } finally {
      submitButton.disabled = false;
    }
  });
});
