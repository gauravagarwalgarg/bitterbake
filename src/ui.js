let currentChart = null;

export function renderDashboard(vulnerabilities) {
  document.getElementById('dashboard-section').classList.remove('hidden');
  renderMetrics(vulnerabilities);
  renderTable(vulnerabilities);
  renderChart(vulnerabilities);
  setupSearch(vulnerabilities);
}

function renderMetrics(vulnerabilities) {
  const total = vulnerabilities.length;
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 };
  
  vulnerabilities.forEach(v => {
    if (counts[v.severity] !== undefined) counts[v.severity]++;
    else counts.UNKNOWN++;
  });

  const container = document.getElementById('metrics-container');
  container.innerHTML = `
    <div class="bg-white rounded-xl shadow p-4 border-l-4 border-slate-500">
      <div class="text-slate-500 text-xs font-bold uppercase tracking-wider">Total</div>
      <div class="text-2xl font-bold text-slate-800 mt-1">${total}</div>
    </div>
    <div class="bg-white rounded-xl shadow p-4 border-l-4 border-red-600">
      <div class="text-slate-500 text-xs font-bold uppercase tracking-wider">Critical</div>
      <div class="text-2xl font-bold text-slate-800 mt-1">${counts.CRITICAL}</div>
    </div>
    <div class="bg-white rounded-xl shadow p-4 border-l-4 border-orange-500">
      <div class="text-slate-500 text-xs font-bold uppercase tracking-wider">High</div>
      <div class="text-2xl font-bold text-slate-800 mt-1">${counts.HIGH}</div>
    </div>
    <div class="bg-white rounded-xl shadow p-4 border-l-4 border-yellow-400">
      <div class="text-slate-500 text-xs font-bold uppercase tracking-wider">Medium</div>
      <div class="text-2xl font-bold text-slate-800 mt-1">${counts.MEDIUM}</div>
    </div>
    <div class="bg-white rounded-xl shadow p-4 border-l-4 border-green-500">
      <div class="text-slate-500 text-xs font-bold uppercase tracking-wider">Low</div>
      <div class="text-2xl font-bold text-slate-800 mt-1">${counts.LOW}</div>
    </div>
  `;
}

function renderTable(vulnerabilities) {
  const tbody = document.getElementById('table-body');
  tbody.innerHTML = '';

  const getSeverityBadge = (sev) => {
    const colors = {
      CRITICAL: 'bg-red-100 text-red-800',
      HIGH: 'bg-orange-100 text-orange-800',
      MEDIUM: 'bg-yellow-100 text-yellow-800',
      LOW: 'bg-green-100 text-green-800'
    };
    const c = colors[sev] || 'bg-slate-100 text-slate-800';
    return `<span class="px-2 py-1 inline-flex text-xs leading-5 font-semibold rounded-full ${c}">${sev}</span>`;
  };

  vulnerabilities.forEach(v => {
    const tr = document.createElement('tr');
    tr.className = 'hover:bg-slate-50 transition-colors';
    if (v.inSbom) tr.classList.add('bg-indigo-50');

    const pkgNames = v.packages.map(p => p.product).slice(0, 3).join(', ') + (v.packages.length > 3 ? '...' : '');

    tr.innerHTML = `
      <td class="px-4 py-3 font-medium">${v.id}</td>
      <td class="px-4 py-3">${getSeverityBadge(v.severity)}</td>
      <td class="px-4 py-3">${v.score.toFixed(1)}</td>
      <td class="px-4 py-3 text-xs truncate max-w-xs" title="${pkgNames}">
        ${v.inSbom ? '<span class="text-indigo-600 font-bold">&#10003; In SBOM</span> ' : ''}
        ${pkgNames || 'N/A'}
      </td>
    `;
    tbody.appendChild(tr);
  });
}

function renderChart(vulnerabilities) {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  vulnerabilities.forEach(v => {
    if (counts[v.severity] !== undefined) counts[v.severity]++;
  });

  const ctx = document.getElementById('risk-chart').getContext('2d');
  if (currentChart) currentChart.destroy();

  currentChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Critical', 'High', 'Medium', 'Low'],
      datasets: [{
        data: [counts.CRITICAL, counts.HIGH, counts.MEDIUM, counts.LOW],
        backgroundColor: ['#dc2626', '#f97316', '#facc15', '#22c55e'],
        borderWidth: 0
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { position: 'right' }
      },
      cutout: '70%'
    }
  });
}

function setupSearch(vulnerabilities) {
  const input = document.getElementById('search-input');
  input.addEventListener('input', (e) => {
    const term = e.target.value.toLowerCase();
    const filtered = vulnerabilities.filter(v => v.id.toLowerCase().includes(term));
    renderTable(filtered);
  });
}
