const form = document.querySelector('#entry-form');
const message = document.querySelector('#form-message');
const riskClass = (level) => `risk ${level.toLowerCase()}`;

async function loadDashboard() {
  const response = await fetch('/api/dashboard');
  const data = await response.json();
  document.querySelector('#accounts').textContent = data.summary.accounts;
  document.querySelector('#reused').textContent = data.summary.reused_accounts;
  document.querySelector('#highest').textContent = data.summary.highest_risk ? `${data.summary.highest_risk}/100` : 'Low';
  document.querySelector('#alerts').innerHTML = data.reuse_groups.length ? data.reuse_groups.map(group => `<article class="alert ${group.level.toLowerCase()}"><div><span class="${riskClass(group.level)}">${group.level} · ${group.score}/100</span><h3>${group.platforms.join(' ↔ ')}</h3></div><p>One password is protecting ${group.platforms.length} accounts. Use unique passwords for each.</p></article>`).join('') : '<p class="empty">No reuse found yet. Add account records to check them.</p>';
  document.querySelector('#entries').innerHTML = data.entries.length ? data.entries.map(entry => `<tr><td>${escapeHtml(entry.platform)}</td><td>${entry.sensitivity}</td><td><span class="${riskClass(entry.risk_level)}">${entry.risk_level} · ${entry.risk_score}/100</span></td><td>${entry.reused_with.length ? escapeHtml(entry.reused_with.join(', ')) : '—'}</td><td><button class="delete" data-id="${entry.id}">Delete</button></td></tr>`).join('') : '<tr><td colspan="5" class="empty">No local records.</td></tr>';
}
function escapeHtml(value) { const element = document.createElement('span'); element.textContent = value; return element.innerHTML; }
form.addEventListener('submit', async event => { event.preventDefault(); message.textContent = 'Checking…'; const values = Object.fromEntries(new FormData(form)); const response = await fetch('/api/entries', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(values)}); const data = await response.json(); message.textContent = response.ok ? data.message : data.error; message.className = `message ${response.ok && data.reused ? 'warning' : response.ok ? 'success' : 'error'}`; if (response.ok) { form.reset(); await loadDashboard(); } });
document.querySelector('#entries').addEventListener('click', async event => { if (!event.target.matches('.delete')) return; await fetch(`/api/entries/${event.target.dataset.id}`, {method: 'DELETE'}); await loadDashboard(); });
loadDashboard();
