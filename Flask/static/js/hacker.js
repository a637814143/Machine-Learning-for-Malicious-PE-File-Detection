const $ = (selector, scope = document) => scope.querySelector(selector);
const $$ = (selector, scope = document) => Array.from(scope.querySelectorAll(selector));

const formatter = new Intl.DateTimeFormat(undefined, {
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
});

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
  requestBlock.textContent = `请求\n${request}`;

  const responseBlock = document.createElement('pre');
  responseBlock.textContent = `响应\n${response}`;

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
  verdict.textContent = malicious ? '恶意' : '良性';

  const score = document.createElement('span');
  score.className = 'result-card__score';
  const probability = Number(data.probability ?? 0);
  const displayProbability = data.display_probability ?? `${(probability * 100).toFixed(2)}%`;
  score.textContent = `置信度：${displayProbability}`;

  header.append(verdict, score);

  const meta = document.createElement('div');
  meta.className = 'result-card__meta';
  const risk = data?.summary?.risk_assessment ?? {};
  const riskLevel = risk?.level ? `${risk.level} (得分 ${Number(risk.score ?? 0).toFixed(1)}/10)` : '未知';
  meta.innerHTML = `
    <p><strong>文件：</strong> ${data.file_path ?? '未知'}</p>
    <p><strong>风险评估：</strong> ${riskLevel}</p>
    <p><strong>使用模型：</strong> ${data.model_path ?? 'model.txt'}</p>
    <p><strong>判定阈值：</strong> ${(Number(data.threshold ?? 0).toFixed(4))}</p>
  `;

  const reasoning = document.createElement('div');
  reasoning.className = 'result-card__reasoning';
  const headline = data?.reasoning?.headline;
  if (headline) {
    const heading = document.createElement('h3');
    heading.textContent = headline;
    reasoning.append(heading);
  }

  const bullets = Array.isArray(data?.reasoning?.bullets) ? data.reasoning.bullets.slice(0, 5) : [];
  if (bullets.length > 0) {
    const list = document.createElement('ul');
    list.className = 'result-card__bullets';
    bullets.forEach((item) => {
      const li = document.createElement('li');
      li.textContent = item;
      list.append(li);
    });
    reasoning.append(list);
  }

  const actions = document.createElement('div');
  actions.className = 'result-card__actions';

  const downloadBtn = document.createElement('button');
  downloadBtn.type = 'button';
  downloadBtn.className = 'btn btn--secondary';
  downloadBtn.textContent = '下载报告';
  downloadBtn.addEventListener('click', () => {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    const fallbackName = (data.file_path ? data.file_path.split(/\\|\//).pop() : 'report') || 'report';
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    anchor.href = url;
    anchor.download = `${fallbackName}-report-${stamp}.json`;
    document.body.append(anchor);
    anchor.click();
    anchor.remove();
    setTimeout(() => URL.revokeObjectURL(url), 0);
  });

  const detailToggle = document.createElement('details');
  detailToggle.className = 'result-card__details';
  const summary = document.createElement('summary');
  summary.textContent = '查看原始数据';
  const raw = document.createElement('pre');
  raw.className = 'result-card__json';
  raw.textContent = JSON.stringify(data, null, 2);
  detailToggle.append(summary, raw);

  actions.append(downloadBtn, detailToggle);

  card.append(header, meta, reasoning, actions);
  results.prepend(card);
}

function serialiseForm({ mode, file, pathValue }) {
  if (mode === 'upload') {
    if (!file) {
      throw new Error('请选择需要扫描的文件。');
    }
    const formData = new FormData();
    formData.append('file', file);
    return { body: formData, headers: undefined };
  }

  if (!pathValue) {
    throw new Error("请输入服务器上的文件路径。");
  }

  const payload = { path: pathValue };
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

    let requestDescription = '';
    let body;
    let headers;

    try {
      ({ body, headers } = serialiseForm({ mode, file, pathValue }));
      requestDescription = mode === 'upload'
        ? `POST /predict (multipart)\nfile=${file?.name ?? 'n/a'}`
        : `POST /predict (json)\npath=${pathValue}`;
    } catch (error) {
      setStatus(error.message, { busy: false, tone: 'error' });
      submitButton.disabled = false;
      return;
    }

    setStatus('正在传输样本...', { busy: true });

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
      setStatus('检测完成，报告已生成。', { busy: false, tone: 'success' });
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
