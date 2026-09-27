import './style.css';
import { parseCVE } from './parser.js';
import { parseSPDX } from './spdx.js';
import { correlate } from './correlator.js';
import { renderDashboard } from './ui.js';

let cveData = null;
let spdxData = null;

function setupDragAndDrop(zoneId, inputId, labelId, onFileLoaded) {
  const zone = document.getElementById(zoneId);
  const input = document.getElementById(inputId);
  const label = document.getElementById(labelId);

  zone.addEventListener('click', () => input.click());

  zone.addEventListener('dragover', (e) => {
    e.preventDefault();
    zone.classList.add('border-indigo-500', 'bg-indigo-50');
  });

  zone.addEventListener('dragleave', () => {
    zone.classList.remove('border-indigo-500', 'bg-indigo-50');
  });

  zone.addEventListener('drop', (e) => {
    e.preventDefault();
    zone.classList.remove('border-indigo-500', 'bg-indigo-50');
    if (e.dataTransfer.files.length) {
      handleFile(e.dataTransfer.files[0]);
    }
  });

  input.addEventListener('change', (e) => {
    if (e.target.files.length) {
      handleFile(e.target.files[0]);
    }
  });

  function handleFile(file) {
    label.textContent = file.name;
    const reader = new FileReader();
    reader.onload = (event) => {
      try {
        const json = JSON.parse(event.target.result);
        onFileLoaded(json);
        checkReady();
      } catch (err) {
        alert('Invalid JSON file.');
      }
    };
    reader.readAsText(file);
  }
}

function checkReady() {
  const btn = document.getElementById('btn-process');
  if (cveData) {
    btn.disabled = false;
    btn.classList.remove('opacity-50', 'cursor-not-allowed');
  } else {
    btn.disabled = true;
    btn.classList.add('opacity-50', 'cursor-not-allowed');
  }
}

document.addEventListener('DOMContentLoaded', () => {
  setupDragAndDrop('drop-zone-cve', 'file-input-cve', 'cve-file-name', (json) => {
    cveData = json;
  });

  setupDragAndDrop('drop-zone-spdx', 'file-input-spdx', 'spdx-file-name', (json) => {
    spdxData = json;
  });

  document.getElementById('btn-process').addEventListener('click', () => {
    if (!cveData) return;
    const cves = parseCVE(cveData);
    let correlated = cves;
    
    if (spdxData) {
      const spdx = parseSPDX(spdxData);
      correlated = correlate(cves, spdx);
    }
    
    renderDashboard(correlated);
  });
});
