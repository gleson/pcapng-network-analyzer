/**
 * PCAP Network Analyzer - Frontend JavaScript
 * Gerencia upload, análise e visualização de resultados
 * Com suporte a PostgreSQL, dark mode, filtro por período e geolocalização
 */

// Estado global
let currentData = null;
let trafficChart = null;
let protocolChart = null;
let statusCheckInterval = null;
let ipsDataTable = null;
let protocolsDataTable = null;
let currentViewMode = 'single';  // 'single' ou 'aggregate'
let selectedScanIds = [];

// ==================== INICIALIZAÇÃO ====================

$(document).ready(function() {
    console.log('PCAP Analyzer initialized');

    // Carregar tema salvo
    loadTheme();

    // Event listeners - Upload
    $('#pcap-file').on('change', handleFileSelect);
    $('#upload-btn').on('click', uploadFile);

    // Event listeners - Settings
    $('#save-thresholds-btn').on('click', saveThresholds);
    $('#add-range-btn').on('click', addTrustedRange);
    $('#clear-analysis-btn').on('click', clearAnalysis);

    // Event listeners - Filtros de alertas
    $('[data-filter]').on('click', function() {
        const filter = $(this).data('filter');
        filterAlerts(filter);
        $('[data-filter]').removeClass('active');
        $(this).addClass('active');
    });

    // Event listeners - View mode
    $('#view-single-btn').on('click', function() {
        setViewMode('single');
    });
    $('#view-aggregate-btn').on('click', function() {
        setViewMode('aggregate');
    });

    // Event listeners - Scan selection
    $('#select-all-scans').on('change', function() {
        $('.scan-checkbox').prop('checked', $(this).prop('checked'));
        updateSelectedScans();
    });

    $(document).on('change', '.scan-checkbox', function() {
        updateSelectedScans();
    });

    // Event listeners - Aggregate actions
    $('#view-selected-btn').on('click', viewSelectedScans);
    $('#view-all-btn').on('click', viewAllScans);
    $('#close-aggregate-view').on('click', closeAggregateView);

    // Event listeners - IP Names
    $('#save-ip-name-btn').on('click', saveIpName);
    $('#add-ip-name-btn').on('click', addIpNameFromModal);

    // Event listeners - Modals
    $('#ipNamesModal').on('show.bs.modal', loadIpNamesModal);

    // Carregar configurações e histórico
    loadSettings();
    loadScanHistory();

    // Verificar se há resultados salvos
    checkForResults();
});

// ==================== DARK MODE ====================

function toggleTheme() {
    const html = document.documentElement;
    const currentTheme = html.getAttribute('data-theme');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';

    html.setAttribute('data-theme', newTheme);
    localStorage.setItem('pcap-analyzer-theme', newTheme);
    updateThemeIcon(newTheme);
    updateChartColors(newTheme);
}

function loadTheme() {
    const savedTheme = localStorage.getItem('pcap-analyzer-theme') || 'light';
    document.documentElement.setAttribute('data-theme', savedTheme);
    updateThemeIcon(savedTheme);
}

function updateThemeIcon(theme) {
    const icon = document.getElementById('theme-icon');
    if (icon) {
        icon.className = theme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
    }
}

function updateChartColors(theme) {
    const textColor = theme === 'dark' ? '#e0e0e0' : '#666';
    const gridColor = theme === 'dark' ? 'rgba(255,255,255,0.1)' : 'rgba(0,0,0,0.1)';

    if (trafficChart) {
        trafficChart.options.scales.x.ticks.color = textColor;
        trafficChart.options.scales.y.ticks.color = textColor;
        trafficChart.options.scales.x.grid.color = gridColor;
        trafficChart.options.scales.y.grid.color = gridColor;
        trafficChart.update();
    }
    if (protocolChart) {
        protocolChart.options.plugins.legend.labels.color = textColor;
        protocolChart.update();
    }
}

// ==================== DATE FILTER ====================

function applyDateFilter() {
    const dateFrom = $('#filter-date-from').val();
    const dateTo = $('#filter-date-to').val();

    if (!dateFrom && !dateTo) {
        alert('Selecione pelo menos uma data para filtrar.');
        return;
    }

    loadScanHistory(dateFrom, dateTo);

    // Mostrar indicação do filtro ativo
    let filterText = 'Filtro ativo: ';
    if (dateFrom && dateTo) {
        filterText += `${formatDateBR(dateFrom)} a ${formatDateBR(dateTo)}`;
    } else if (dateFrom) {
        filterText += `a partir de ${formatDateBR(dateFrom)}`;
    } else {
        filterText += `até ${formatDateBR(dateTo)}`;
    }
    $('#filter-status-text').text(filterText).addClass('text-primary');
}

function clearDateFilter() {
    $('#filter-date-from').val('');
    $('#filter-date-to').val('');
    $('#filter-status-text').text('').removeClass('text-primary');
    loadScanHistory();
}

function formatDateBR(dateStr) {
    const parts = dateStr.split('-');
    return `${parts[2]}/${parts[1]}/${parts[0]}`;
}

// ==================== VIEW MODE ====================

function setViewMode(mode) {
    currentViewMode = mode;

    if (mode === 'single') {
        $('#view-single-btn').addClass('active');
        $('#view-aggregate-btn').removeClass('active');
        $('#aggregate-actions').hide();
        $('.scan-checkbox, #select-all-scans').prop('checked', false);
    } else {
        $('#view-single-btn').removeClass('active');
        $('#view-aggregate-btn').addClass('active');
        $('#aggregate-actions').show();
    }
}

function updateSelectedScans() {
    selectedScanIds = [];
    $('.scan-checkbox:checked').each(function() {
        selectedScanIds.push(parseInt($(this).data('scan-id')));
    });

    if (selectedScanIds.length > 0) {
        $('#view-selected-btn').prop('disabled', false);
    } else {
        $('#view-selected-btn').prop('disabled', true);
    }
}

function viewSelectedScans() {
    if (selectedScanIds.length === 0) {
        alert('Selecione pelo menos um scan');
        return;
    }

    const dateFrom = $('#filter-date-from').val();
    const dateTo = $('#filter-date-to').val();
    loadResults(null, 'aggregate', selectedScanIds, dateFrom, dateTo);
    $('#view-mode-indicator').show();
    $('#view-mode-text').text(`Visualizando: ${selectedScanIds.length} scans selecionados (Agregado)`);
}

function viewAllScans() {
    const dateFrom = $('#filter-date-from').val();
    const dateTo = $('#filter-date-to').val();
    loadResults(null, 'aggregate', null, dateFrom, dateTo);
    $('#view-mode-indicator').show();

    let text = 'Visualizando: Todos os scans (Agregado)';
    if (dateFrom || dateTo) {
        text += ' - com filtro de período';
    }
    $('#view-mode-text').text(text);
}

function closeAggregateView() {
    $('#view-mode-indicator').hide();
    checkForResults();
}

// ==================== SCAN HISTORY ====================

function loadScanHistory(dateFrom, dateTo) {
    let url = '/api/scans';
    const params = [];

    if (dateFrom) params.push('date_from=' + dateFrom);
    if (dateTo) params.push('date_to=' + dateTo);

    if (params.length > 0) {
        url += '?' + params.join('&');
    }

    $.ajax({
        url: url,
        type: 'GET',
        success: function(response) {
            if (response.success) {
                renderScanHistory(response.data);
            }
        },
        error: function(xhr) {
            console.error('Error loading scan history:', xhr);
        }
    });
}

function renderScanHistory(scans) {
    const tbody = $('#scans-tbody');
    tbody.empty();

    if (!scans || scans.length === 0) {
        tbody.html(`
            <tr>
                <td colspan="8" class="text-center text-muted">
                    Nenhum scan realizado ainda
                </td>
            </tr>
        `);
        return;
    }

    scans.forEach(scan => {
        const date = new Date(scan.analyzed_at).toLocaleString('pt-BR');
        const alertBadge = scan.alert_count > 0 ?
            `<span class="badge bg-danger">${scan.alert_count}</span>` :
            `<span class="badge bg-success">0</span>`;

        const row = `
            <tr>
                <td><input type="checkbox" class="scan-checkbox" data-scan-id="${scan.id}" value="${scan.id}"></td>
                <td><code>${scan.filename}</code></td>
                <td><small>${date}</small></td>
                <td>${formatNumber(scan.packet_count)}</td>
                <td>${formatBytes(scan.total_bytes)}</td>
                <td>${scan.ip_count}</td>
                <td>${alertBadge}</td>
                <td>
                    <button class="btn btn-sm btn-outline-primary" onclick="viewScan(${scan.id})" title="Ver">
                        <i class="fas fa-eye"></i>
                    </button>
                    <button class="btn btn-sm btn-outline-danger" onclick="deleteScan(${scan.id})" title="Excluir">
                        <i class="fas fa-trash"></i>
                    </button>
                </td>
            </tr>
        `;
        tbody.append(row);
    });
}

function viewScan(scanId) {
    loadResults(scanId, 'single');
    $('#view-mode-indicator').hide();
}

function deleteScan(scanId) {
    if (!confirm('Tem certeza que deseja excluir este scan?\n\nOs dados da análise e o arquivo PCAP serão removidos permanentemente.')) {
        return;
    }

    $.ajax({
        url: `/api/scans/${scanId}`,
        type: 'DELETE',
        success: function(response) {
            if (response.success) {
                loadScanHistory();
                alert('Scan excluído com sucesso');
            }
        },
        error: function(xhr) {
            alert('Erro ao excluir scan');
        }
    });
}

function deleteSelectedScans() {
    const selectedIds = [];
    $('.scan-checkbox:checked').each(function() {
        selectedIds.push(parseInt($(this).val()));
    });

    if (selectedIds.length === 0) {
        alert('Nenhum scan selecionado para exclusão.');
        return;
    }

    if (!confirm(`Tem certeza que deseja excluir ${selectedIds.length} scan(s)?\n\nOs dados das análises e os arquivos PCAP serão removidos permanentemente. Esta ação não pode ser desfeita.`)) {
        return;
    }

    $.ajax({
        url: '/api/scans/batch',
        type: 'DELETE',
        contentType: 'application/json',
        data: JSON.stringify({ ids: selectedIds }),
        success: function(response) {
            if (response.success) {
                loadScanHistory();
                alert(response.message);
            }
        },
        error: function(xhr) {
            alert('Erro ao excluir scans selecionados');
        }
    });
}

// ==================== UPLOAD E ANÁLISE ====================

function handleFileSelect() {
    const file = $('#pcap-file')[0].files[0];
    if (file) {
        $('#upload-btn').prop('disabled', false);
    } else {
        $('#upload-btn').prop('disabled', true);
    }
}

function uploadFile() {
    const fileInput = $('#pcap-file')[0];
    const file = fileInput.files[0];

    if (!file) {
        alert('Por favor, selecione um arquivo');
        return;
    }

    // Verificar extensão
    const validExtensions = ['pcap', 'pcapng'];
    const extension = file.name.split('.').pop().toLowerCase();

    if (!validExtensions.includes(extension)) {
        alert('Arquivo inválido. Use .pcap ou .pcapng');
        return;
    }

    // Preparar FormData
    const formData = new FormData();
    formData.append('file', file);

    // Mostrar progresso
    $('#upload-progress').show();
    $('#upload-btn').prop('disabled', true);
    updateStatus('analyzing', 'Uploading file...');

    // Upload
    $.ajax({
        url: '/api/upload',
        type: 'POST',
        data: formData,
        processData: false,
        contentType: false,
        success: function(response) {
            console.log('Upload successful:', response);
            startStatusPolling();
        },
        error: function(xhr) {
            console.error('Upload error:', xhr);
            const error = xhr.responseJSON?.error || 'Erro no upload';
            alert('Erro: ' + error);
            $('#upload-progress').hide();
            $('#upload-btn').prop('disabled', false);
            updateStatus('idle', 'Idle');
        }
    });
}

function startStatusPolling() {
    if (statusCheckInterval) {
        clearInterval(statusCheckInterval);
    }
    statusCheckInterval = setInterval(checkStatus, 500);
}

function checkStatus() {
    $.ajax({
        url: '/api/status',
        type: 'GET',
        success: function(status) {
            updateStatus(status.status, status.message);

            const progress = status.progress || 0;
            $('#progress-bar').css('width', progress + '%').text(progress + '%');
            $('#progress-message').text(status.message || 'Processing...');

            if (status.status === 'completed') {
                clearInterval(statusCheckInterval);
                setTimeout(() => {
                    loadResults();
                    loadScanHistory();
                    $('#upload-progress').hide();
                    $('#upload-btn').prop('disabled', false);
                    $('#pcap-file').val('');
                }, 500);
            }

            if (status.status === 'error') {
                clearInterval(statusCheckInterval);
                alert('Erro na análise: ' + status.message);
                $('#upload-progress').hide();
                $('#upload-btn').prop('disabled', false);
                updateStatus('idle', 'Idle');
            }
        },
        error: function(xhr) {
            console.error('Error checking status:', xhr);
            clearInterval(statusCheckInterval);
        }
    });
}

function updateStatus(status, message) {
    const statusIndicator = $('#status-indicator i');
    const statusText = $('#status-text');

    switch(status) {
        case 'idle':
            statusIndicator.removeClass().addClass('fas fa-circle text-secondary');
            break;
        case 'analyzing':
            statusIndicator.removeClass().addClass('fas fa-spinner fa-spin text-primary');
            break;
        case 'completed':
            statusIndicator.removeClass().addClass('fas fa-check-circle text-success');
            break;
        case 'error':
            statusIndicator.removeClass().addClass('fas fa-times-circle text-danger');
            break;
    }

    statusText.text(message || status);
}

// ==================== CARREGAMENTO DE RESULTADOS ====================

function checkForResults() {
    $.ajax({
        url: '/api/results',
        type: 'GET',
        success: function(response) {
            if (response.success && response.data) {
                loadResults();
            }
        },
        error: function() {
            // Sem resultados, ignorar
        }
    });
}

function loadResults(scanId = null, view = 'single', scanIds = null, dateFrom = null, dateTo = null) {
    let url = '/api/results';
    const params = [];

    if (view === 'aggregate') {
        params.push('view=aggregate');
        if (scanIds && scanIds.length > 0) {
            params.push('scan_ids=' + scanIds.join(','));
        }
        if (dateFrom) params.push('date_from=' + dateFrom);
        if (dateTo) params.push('date_to=' + dateTo);
    } else if (scanId) {
        params.push('scan_id=' + scanId);
    }

    if (params.length > 0) {
        url += '?' + params.join('&');
    }

    $.ajax({
        url: url,
        type: 'GET',
        success: function(response) {
            if (response.success && response.data) {
                currentData = response.data;
                renderResults(currentData);
                $('#results-section').fadeIn();
                updateStatus('completed', 'Analysis completed');
            }
        },
        error: function(xhr) {
            console.error('Error loading results:', xhr);
            if (xhr.status !== 404) {
                alert('Erro ao carregar resultados');
            }
        }
    });
}

function renderResults(data) {
    renderOverview(data);
    renderIPs(data);
    renderProtocols(data);
    renderAlerts(data);
}

// ==================== RENDERIZAÇÃO: VISÃO GERAL ====================

function renderOverview(data) {
    const summary = data.summary || {};
    const alerts = data.alerts || [];
    const protocols = data.protocols || [];
    const ips = data.ips || [];

    // Métricas
    $('#metric-packets').text(formatNumber(summary.packet_count || 0));
    $('#metric-bytes').text(formatBytes(summary.total_bytes || 0));
    $('#metric-duration').text(formatDuration(summary.duration || 0));
    $('#metric-ips').text(ips.length);
    $('#metric-protocols').text(protocols.length);
    $('#metric-alerts').text(alerts.length);
    $('#alerts-badge').text(alerts.length);

    // Gráficos
    renderTrafficChart(data.traffic_timeline || []);
    renderProtocolChart(protocols);

    // Alertas recentes
    renderRecentAlerts(alerts.slice(0, 5));
}

function renderTrafficChart(timeline) {
    const ctx = document.getElementById('traffic-chart');
    if (!ctx) return;

    if (trafficChart) {
        trafficChart.destroy();
    }

    const theme = document.documentElement.getAttribute('data-theme');
    const textColor = theme === 'dark' ? '#e0e0e0' : '#666';
    const gridColor = theme === 'dark' ? 'rgba(255,255,255,0.1)' : 'rgba(0,0,0,0.1)';

    if (!timeline || timeline.length === 0) {
        trafficChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: ['Sem dados'],
                datasets: [{
                    label: 'Bytes',
                    data: [0],
                    borderColor: 'rgb(75, 192, 192)',
                    backgroundColor: 'rgba(75, 192, 192, 0.2)',
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: { ticks: { color: textColor }, grid: { color: gridColor } },
                    y: { ticks: { color: textColor }, grid: { color: gridColor } }
                }
            }
        });
        return;
    }

    const labels = timeline.map(t => {
        const date = new Date(t.timestamp * 1000);
        return date.toLocaleTimeString();
    });

    const data = timeline.map(t => t.bytes);

    trafficChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: 'Bytes',
                data: data,
                borderColor: 'rgb(75, 192, 192)',
                backgroundColor: 'rgba(75, 192, 192, 0.2)',
                tension: 0.1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false }
            },
            scales: {
                x: { ticks: { color: textColor }, grid: { color: gridColor } },
                y: {
                    beginAtZero: true,
                    ticks: {
                        color: textColor,
                        callback: function(value) {
                            return formatBytes(value);
                        }
                    },
                    grid: { color: gridColor }
                }
            }
        }
    });
}

function renderProtocolChart(protocols) {
    const ctx = document.getElementById('protocol-chart');
    if (!ctx) return;

    if (protocolChart) {
        protocolChart.destroy();
    }

    const theme = document.documentElement.getAttribute('data-theme');
    const textColor = theme === 'dark' ? '#e0e0e0' : '#666';

    const top5 = protocols.slice(0, 5);
    const labels = top5.map(p => p.name);
    const data = top5.map(p => p.bytes);

    const colors = [
        'rgba(255, 99, 132, 0.8)',
        'rgba(54, 162, 235, 0.8)',
        'rgba(255, 206, 86, 0.8)',
        'rgba(75, 192, 192, 0.8)',
        'rgba(153, 102, 255, 0.8)'
    ];

    protocolChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: data,
                backgroundColor: colors
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: textColor }
                }
            }
        }
    });
}

function renderRecentAlerts(alerts) {
    const container = $('#recent-alerts');
    container.empty();

    if (alerts.length === 0) {
        container.html('<p class="text-muted">Nenhum alerta detectado</p>');
        return;
    }

    alerts.forEach(alert => {
        const severityClass = getSeverityClass(alert.severity);
        const severityIcon = getSeverityIcon(alert.severity);

        const alertHtml = `
            <div class="alert alert-${severityClass} alert-dismissible fade show" role="alert">
                <i class="${severityIcon}"></i>
                <strong>${alert.title}</strong><br>
                ${alert.description}
                ${alert.ip ? `<br><small>IP: ${alert.ip}</small>` : ''}
                ${alert.filename ? `<br><small class="text-muted">Arquivo: ${alert.filename}</small>` : ''}
            </div>
        `;

        container.append(alertHtml);
    });
}

// ==================== RENDERIZAÇÃO: IPs ====================

function renderIPs(data) {
    const ips = data.ips || [];
    const tbody = $('#ips-tbody');
    tbody.empty();

    if (ipsDataTable) {
        ipsDataTable.destroy();
    }

    ips.forEach(ip => {
        const typeLabel = ip.is_local ?
            '<span class="badge bg-primary">Local</span>' :
            '<span class="badge bg-secondary">Externo</span>';

        const protocolsBadges = ip.protocols.map(p =>
            `<span class="badge bg-info">${p}</span>`
        ).join(' ');

        const alertsBadge = ip.alert_count > 0 ?
            `<span class="badge bg-danger">${ip.alert_count}</span>` :
            '<span class="badge bg-success">0</span>';

        const nameCell = ip.name ?
            `<span class="text-success">${escapeHtml(ip.name)}</span>` :
            '<span class="text-muted">-</span>';

        const groupCell = ip.group ?
            `<span class="badge bg-info">${escapeHtml(ip.group)}</span>` :
            '<span class="text-muted">-</span>';

        // Geolocalização
        let geoCell = '<span class="text-muted">-</span>';
        if (ip.geolocation) {
            const geo = ip.geolocation;
            const flag = getCountryFlag(geo.country_code);
            geoCell = `<span title="${geo.city || ''}, ${geo.region || ''}, ${geo.country || ''} | ISP: ${geo.isp || ''}">${flag} ${geo.country || ''}</span>`;
            if (geo.city) {
                geoCell = `<span title="${geo.city}, ${geo.region || ''}, ${geo.country || ''} | ISP: ${geo.isp || ''}">${flag} ${geo.city}</span>`;
            }
        } else if (ip.is_local) {
            geoCell = '<span class="text-muted">Local</span>';
        }

        const row = `
            <tr>
                <td><code>${ip.ip}</code></td>
                <td>${nameCell}</td>
                <td>${groupCell}</td>
                <td>${typeLabel}</td>
                <td>${geoCell}</td>
                <td>${formatNumber(ip.packets_sent)}</td>
                <td>${formatNumber(ip.packets_received)}</td>
                <td>${formatBytes(ip.bytes_sent)}</td>
                <td>${formatBytes(ip.bytes_received)}</td>
                <td>${protocolsBadges || '-'}</td>
                <td>${alertsBadge}</td>
                <td>
                    <button class="btn btn-sm btn-outline-primary" onclick="editIpName('${ip.ip}', '${escapeHtml(ip.name || '')}', '')" title="Editar Nome">
                        <i class="fas fa-edit"></i>
                    </button>
                    <button class="btn btn-sm btn-outline-info" onclick="showIpEvolution('${ip.ip}')" title="Ver Evolução">
                        <i class="fas fa-chart-line"></i>
                    </button>
                </td>
            </tr>
        `;

        tbody.append(row);
    });

    ipsDataTable = $('#ips-table').DataTable({
        order: [[7, 'desc']],  // Ordenar por bytes enviados
        pageLength: 25,
        language: {
            url: '//cdn.datatables.net/plug-ins/1.13.6/i18n/pt-BR.json'
        }
    });
}

function getCountryFlag(countryCode) {
    if (!countryCode) return '';
    const codePoints = countryCode
        .toUpperCase()
        .split('')
        .map(char => 127397 + char.charCodeAt(0));
    return String.fromCodePoint(...codePoints);
}

// ==================== RENDERIZAÇÃO: PROTOCOLOS ====================

function renderProtocols(data) {
    const protocols = data.protocols || [];
    const tbody = $('#protocols-tbody');
    tbody.empty();

    if (protocolsDataTable) {
        protocolsDataTable.destroy();
    }

    protocols.forEach(proto => {
        const riskBadge = getRiskBadge(proto.risk_level);

        const warningCell = proto.warning ?
            `<i class="fas fa-exclamation-circle text-warning" title="${proto.warning}"></i> ${proto.warning}` :
            '<span class="text-muted">-</span>';

        const row = `
            <tr class="protocol-row" data-protocol="${proto.name}" style="cursor: pointer;" onclick="showProtocolIPs('${proto.name}')">
                <td><strong>${proto.name}</strong> <i class="fas fa-search text-muted" title="Clique para ver IPs"></i></td>
                <td>${formatNumber(proto.packets)}</td>
                <td>${formatBytes(proto.bytes)}</td>
                <td>${proto.percentage}%</td>
                <td>${riskBadge}</td>
                <td>${warningCell}</td>
            </tr>
        `;

        tbody.append(row);
    });

    protocolsDataTable = $('#protocols-table').DataTable({
        order: [[2, 'desc']],
        pageLength: 25,
        language: {
            url: '//cdn.datatables.net/plug-ins/1.13.6/i18n/pt-BR.json'
        }
    });
}

function showProtocolIPs(protocolName) {
    if (!currentData) return;

    const protocolIps = currentData.protocol_ips ? currentData.protocol_ips[protocolName] : null;

    let content = `<h6>IPs que utilizaram ${protocolName}:</h6>`;

    if (protocolIps && protocolIps.length > 0) {
        content += '<div class="table-responsive"><table class="table table-sm table-striped"><thead><tr><th>IP</th><th>Nome</th><th>Tipo</th><th>Pacotes</th><th>Bytes</th></tr></thead><tbody>';

        const ipNames = {};
        if (currentData.ips) {
            currentData.ips.forEach(ip => {
                ipNames[ip.ip] = ip.name || '';
            });
        }

        protocolIps.forEach(ipData => {
            const typeLabel = ipData.is_local ?
                '<span class="badge bg-primary">Local</span>' :
                '<span class="badge bg-secondary">Externo</span>';
            const name = ipData.name || ipNames[ipData.ip] || '-';

            content += `<tr>
                <td><code>${ipData.ip}</code></td>
                <td>${escapeHtml(name)}</td>
                <td>${typeLabel}</td>
                <td>${formatNumber(ipData.packets)}</td>
                <td>${formatBytes(ipData.bytes)}</td>
            </tr>`;
        });

        content += '</tbody></table></div>';

        const totalPackets = protocolIps.reduce((sum, ip) => sum + ip.packets, 0);
        const totalBytes = protocolIps.reduce((sum, ip) => sum + ip.bytes, 0);
        const localCount = protocolIps.filter(ip => ip.is_local).length;
        const externalCount = protocolIps.length - localCount;

        content += `<hr><div class="row text-center">
            <div class="col-3">
                <strong>${protocolIps.length}</strong><br><small class="text-muted">IPs Total</small>
            </div>
            <div class="col-3">
                <strong>${localCount}</strong><br><small class="text-muted">Locais</small>
            </div>
            <div class="col-3">
                <strong>${externalCount}</strong><br><small class="text-muted">Externos</small>
            </div>
            <div class="col-3">
                <strong>${formatBytes(totalBytes)}</strong><br><small class="text-muted">Total</small>
            </div>
        </div>`;

    } else {
        const ipsWithProtocol = currentData.ips ? currentData.ips.filter(ip =>
            ip.protocols && ip.protocols.includes(protocolName)
        ) : [];

        if (ipsWithProtocol.length === 0) {
            content += '<p class="text-muted">Nenhum IP encontrado</p>';
        } else {
            content += '<div class="table-responsive"><table class="table table-sm"><thead><tr><th>IP</th><th>Nome</th><th>Tipo</th><th>Bytes Env.</th><th>Bytes Rec.</th></tr></thead><tbody>';

            ipsWithProtocol.forEach(ip => {
                const typeLabel = ip.is_local ? 'Local' : 'Externo';
                const name = ip.name || '-';
                content += `<tr><td><code>${ip.ip}</code></td><td>${name}</td><td>${typeLabel}</td><td>${formatBytes(ip.bytes_sent)}</td><td>${formatBytes(ip.bytes_received)}</td></tr>`;
            });

            content += '</tbody></table></div>';
        }
    }

    $('#evolution-ip').text(protocolName);
    $('#evolution-content').html(content);
    $('#ipEvolutionModal .modal-title').html(`<i class="fas fa-layer-group"></i> Protocolo: ${protocolName}`);
    new bootstrap.Modal('#ipEvolutionModal').show();
}

// ==================== RENDERIZAÇÃO: ALERTAS ====================

function renderAlerts(data) {
    const alerts = data.alerts || [];
    const container = $('#alerts-list');
    container.empty();

    if (alerts.length === 0) {
        container.html('<p class="text-muted">Nenhum alerta detectado</p>');
        return;
    }

    alerts.forEach((alert, index) => {
        const severityClass = getSeverityClass(alert.severity);
        const severityIcon = getSeverityIcon(alert.severity);

        const alertHtml = `
            <div class="alert-item alert alert-${severityClass}" data-severity="${alert.severity}">
                <div class="d-flex justify-content-between align-items-start">
                    <div class="flex-grow-1">
                        <h6>
                            <i class="${severityIcon}"></i>
                            ${alert.title}
                            <span class="badge bg-${severityClass}">${alert.severity.toUpperCase()}</span>
                        </h6>
                        <p class="mb-1">${alert.description}</p>
                        ${alert.ip ? `<p class="mb-1"><strong>IP:</strong> <code>${alert.ip}</code></p>` : ''}
                        <p class="mb-1"><strong>Categoria:</strong> ${alert.category}</p>
                        ${alert.filename ? `<p class="mb-1"><small class="text-muted">Arquivo: ${alert.filename}</small></p>` : ''}
                        <p class="mb-2"><em>${alert.recommendation}</em></p>
                        ${renderAlertDetails(alert.details)}
                    </div>
                </div>
            </div>
        `;

        container.append(alertHtml);
    });
}

function renderAlertDetails(details) {
    if (!details || Object.keys(details).length === 0) {
        return '';
    }

    let html = '<div class="alert-details"><strong>Detalhes:</strong><ul class="mb-0">';

    for (const [key, value] of Object.entries(details)) {
        let displayValue = value;

        if (Array.isArray(value)) {
            displayValue = value.join(', ');
        }

        html += `<li><strong>${key}:</strong> ${displayValue}</li>`;
    }

    html += '</ul></div>';
    return html;
}

function filterAlerts(severity) {
    if (severity === 'all') {
        $('.alert-item').show();
    } else {
        $('.alert-item').hide();
        $(`.alert-item[data-severity="${severity}"]`).show();
    }
}

// ==================== IP NAMES ====================

function editIpName(ip, currentName, currentDesc) {
    $('#edit-ip-address').val(ip);
    $('#edit-ip-name').val(currentName);
    $('#edit-ip-description').val(currentDesc);

    new bootstrap.Modal('#editIpNameModal').show();
}

function saveIpName() {
    const ip = $('#edit-ip-address').val();
    const name = $('#edit-ip-name').val().trim();
    const description = $('#edit-ip-description').val().trim();

    if (!name) {
        alert('Nome é obrigatório');
        return;
    }

    $.ajax({
        url: '/api/ip-names',
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({ ip, name, description }),
        success: function(response) {
            if (response.success) {
                bootstrap.Modal.getInstance('#editIpNameModal').hide();
                loadResults();
                alert('Nome salvo com sucesso!');
            }
        },
        error: function(xhr) {
            alert('Erro ao salvar nome');
        }
    });
}

function loadIpNamesModal() {
    $.ajax({
        url: '/api/ip-names',
        type: 'GET',
        success: function(response) {
            if (response.success) {
                renderIpNamesTable(response.data);
            }
        }
    });
}

function renderIpNamesTable(ipNames) {
    const tbody = $('#ip-names-tbody');
    tbody.empty();

    const entries = Object.entries(ipNames);

    if (entries.length === 0) {
        tbody.html('<tr><td colspan="4" class="text-center text-muted">Nenhum nome cadastrado</td></tr>');
        return;
    }

    entries.forEach(([ip, info]) => {
        const row = `
            <tr>
                <td><code>${ip}</code></td>
                <td>${escapeHtml(info.name)}</td>
                <td>${escapeHtml(info.description || '-')}</td>
                <td>
                    <button class="btn btn-sm btn-outline-danger" onclick="deleteIpName('${ip}')">
                        <i class="fas fa-trash"></i>
                    </button>
                </td>
            </tr>
        `;
        tbody.append(row);
    });
}

function addIpNameFromModal() {
    const ip = $('#new-ip-address').val().trim();
    const name = $('#new-ip-name').val().trim();
    const description = $('#new-ip-desc').val().trim();

    if (!ip || !name) {
        alert('IP e Nome são obrigatórios');
        return;
    }

    $.ajax({
        url: '/api/ip-names',
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({ ip, name, description }),
        success: function(response) {
            if (response.success) {
                $('#new-ip-address').val('');
                $('#new-ip-name').val('');
                $('#new-ip-desc').val('');
                loadIpNamesModal();
                loadResults();
            }
        },
        error: function(xhr) {
            alert('Erro ao adicionar nome');
        }
    });
}

function deleteIpName(ip) {
    if (!confirm(`Remover nome do IP ${ip}?`)) {
        return;
    }

    const encodedIp = ip.replace(/\./g, '-');

    $.ajax({
        url: `/api/ip-names/${encodedIp}`,
        type: 'DELETE',
        success: function(response) {
            if (response.success) {
                loadIpNamesModal();
                loadResults();
            }
        },
        error: function(xhr) {
            alert('Erro ao remover nome');
        }
    });
}

// ==================== IP EVOLUTION ====================

function showIpEvolution(ip) {
    const encodedIp = ip.replace(/\./g, '-');

    $('#evolution-ip').text(ip);
    $('#evolution-content').html('<p class="text-muted">Carregando...</p>');
    $('#ipEvolutionModal .modal-title').html(`<i class="fas fa-chart-line"></i> Evolução do IP: <span id="evolution-ip">${ip}</span>`);

    new bootstrap.Modal('#ipEvolutionModal').show();

    $.ajax({
        url: `/api/ip-evolution/${encodedIp}`,
        type: 'GET',
        success: function(response) {
            if (response.success) {
                renderIpEvolution(response.data, ip);
            } else {
                $('#evolution-content').html('<p class="text-danger">Erro ao carregar evolução</p>');
            }
        },
        error: function() {
            $('#evolution-content').html('<p class="text-danger">Erro ao carregar evolução</p>');
        }
    });
}

function renderIpEvolution(evolution, ip) {
    const container = $('#evolution-content');

    if (!evolution || evolution.length === 0) {
        container.html('<p class="text-muted">Nenhum histórico encontrado para este IP</p>');
        return;
    }

    let html = `
        <div class="table-responsive">
            <table class="table table-sm table-striped">
                <thead>
                    <tr>
                        <th>Arquivo</th>
                        <th>Data</th>
                        <th>Pacotes Env.</th>
                        <th>Pacotes Rec.</th>
                        <th>Bytes Env.</th>
                        <th>Bytes Rec.</th>
                        <th>Alertas</th>
                    </tr>
                </thead>
                <tbody>
    `;

    evolution.forEach(entry => {
        const date = new Date(entry.analyzed_at).toLocaleString('pt-BR');
        const alertBadge = entry.alert_count > 0 ?
            `<span class="badge bg-danger">${entry.alert_count}</span>` :
            `<span class="badge bg-success">0</span>`;

        html += `
            <tr>
                <td><code>${entry.filename}</code></td>
                <td><small>${date}</small></td>
                <td>${formatNumber(entry.packets_sent)}</td>
                <td>${formatNumber(entry.packets_received)}</td>
                <td>${formatBytes(entry.bytes_sent)}</td>
                <td>${formatBytes(entry.bytes_received)}</td>
                <td>${alertBadge}</td>
            </tr>
        `;
    });

    html += '</tbody></table></div>';

    container.html(html);
}

// ==================== CONFIGURAÇÕES ====================

function loadSettings() {
    $.ajax({
        url: '/api/settings',
        type: 'GET',
        success: function(response) {
            if (response.success && response.data) {
                const settings = response.data;

                const thresholds = settings.thresholds || {};
                $('#threshold-port-scan-min').val(thresholds.port_scan_min_ports || 20);
                $('#threshold-port-scan-time').val(thresholds.port_scan_time_window || 30);
                $('#threshold-arp-gratuitous').val(thresholds.arp_gratuitous_max || 5);
                $('#threshold-dns-subdomain').val(thresholds.dns_subdomain_length || 50);
                $('#threshold-dns-entropy').val(thresholds.dns_entropy_min || 3.5);

                renderTrustedRanges(settings.trusted_ranges || []);
            }
        },
        error: function(xhr) {
            console.error('Error loading settings:', xhr);
        }
    });
}

function saveThresholds() {
    const thresholds = {
        port_scan_min_ports: parseInt($('#threshold-port-scan-min').val()),
        port_scan_time_window: parseInt($('#threshold-port-scan-time').val()),
        arp_gratuitous_max: parseInt($('#threshold-arp-gratuitous').val()),
        dns_subdomain_length: parseInt($('#threshold-dns-subdomain').val()),
        dns_entropy_min: parseFloat($('#threshold-dns-entropy').val())
    };

    $.ajax({
        url: '/api/settings',
        type: 'GET',
        success: function(response) {
            const settings = response.data || {};
            settings.thresholds = thresholds;

            $.ajax({
                url: '/api/settings',
                type: 'POST',
                contentType: 'application/json',
                data: JSON.stringify(settings),
                success: function() {
                    alert('Thresholds salvos com sucesso!');
                },
                error: function(xhr) {
                    alert('Erro ao salvar thresholds');
                }
            });
        }
    });
}

function renderTrustedRanges(ranges) {
    const container = $('#trusted-ranges-list');
    container.empty();

    if (ranges.length === 0) {
        container.html('<p class="text-muted">Nenhum range configurado</p>');
        return;
    }

    ranges.forEach(range => {
        const rangeHtml = `
            <div class="d-flex justify-content-between align-items-center mb-2 p-2 border rounded">
                <div>
                    <code>${range.cidr}</code>
                    <br>
                    <small class="text-muted">${range.description}</small>
                </div>
                <button class="btn btn-sm btn-danger" onclick="deleteTrustedRange('${range.cidr}')">
                    <i class="fas fa-trash"></i>
                </button>
            </div>
        `;
        container.append(rangeHtml);
    });
}

function addTrustedRange() {
    const cidr = $('#new-range-cidr').val().trim();
    const description = $('#new-range-desc').val().trim();

    if (!cidr) {
        alert('CIDR é obrigatório');
        return;
    }

    $.ajax({
        url: '/api/trusted-range',
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({ cidr, description }),
        success: function() {
            $('#new-range-cidr').val('');
            $('#new-range-desc').val('');
            loadSettings();
            alert('Range adicionado com sucesso!');
        },
        error: function(xhr) {
            const error = xhr.responseJSON?.error || 'Erro ao adicionar range';
            alert(error);
        }
    });
}

function deleteTrustedRange(cidr) {
    if (!confirm(`Remover range ${cidr}?`)) {
        return;
    }

    const encodedCidr = cidr.replace('/', '-');

    $.ajax({
        url: `/api/trusted-range/${encodedCidr}`,
        type: 'DELETE',
        success: function() {
            loadSettings();
            alert('Range removido com sucesso!');
        },
        error: function(xhr) {
            alert('Erro ao remover range');
        }
    });
}

function clearAnalysis() {
    if (!confirm('Tem certeza que deseja limpar a análise atual?')) {
        return;
    }

    $.ajax({
        url: '/api/clear',
        type: 'POST',
        success: function() {
            currentData = null;
            $('#results-section').hide();
            updateStatus('idle', 'Idle');
            alert('Análise limpa com sucesso!');
        },
        error: function(xhr) {
            const error = xhr.responseJSON?.error || 'Erro ao limpar análise';
            alert(error);
        }
    });
}

// ==================== UTILITÁRIOS ====================

function formatNumber(num) {
    return num.toLocaleString('pt-BR');
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';

    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));

    return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
}

function formatDuration(seconds) {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = Math.floor(seconds % 60);

    if (hours > 0) {
        return `${hours}h ${minutes}m ${secs}s`;
    } else if (minutes > 0) {
        return `${minutes}m ${secs}s`;
    } else {
        return `${secs}s`;
    }
}

function getSeverityClass(severity) {
    const classes = {
        'critical': 'danger',
        'high': 'warning',
        'medium': 'info',
        'low': 'secondary'
    };
    return classes[severity] || 'secondary';
}

function getSeverityIcon(severity) {
    const icons = {
        'critical': 'fas fa-exclamation-circle',
        'high': 'fas fa-exclamation-triangle',
        'medium': 'fas fa-info-circle',
        'low': 'fas fa-check-circle'
    };
    return icons[severity] || 'fas fa-info-circle';
}

function getRiskBadge(risk) {
    const badges = {
        'low': '<span class="badge bg-success">Baixo</span>',
        'medium': '<span class="badge bg-warning">Médio</span>',
        'high': '<span class="badge bg-danger">Alto</span>'
    };
    return badges[risk] || '<span class="badge bg-secondary">-</span>';
}

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
