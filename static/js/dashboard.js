// 全局变量，用于存储图表实例和模态框实例
let connectionsChart;
let confirmModal;
let limitIpModal;

/**
 * 核心函数：从后端 API 获取数据并更新整个仪表盘
 */
async function updateDashboard() {
    try {
        const response = await fetch('/api/data');
        if (!response.ok) {
            throw new Error(`Network response was not ok, status: ${response.status}`);
        }
        const data = await response.json();

        // 更新所有模块
        updateSystemInfo(data.sys_info);
        updateStatsTable(data.stats);
        updateIpControlLists(data.banned_ips, data.limited_ips);
        updateConnectionsAccordion(data.connections, data.banned_ips, data.limited_ips);
        updateConnectionsChart(data.connections);
        
        // 更新时间戳
        document.getElementById('last-updated').innerText = `最后更新于: ${new Date().toLocaleTimeString()}`;

    } catch (error) {
        console.error('Failed to fetch or process dashboard data:', error);
    }
}

/**
 * 更新系统资源信息模块
 * @param {object} sys_info - 包含 cpu, memory, disk 信息的对象
 */
function updateSystemInfo(sys_info) {
    document.getElementById('cpu-usage').innerText = `${sys_info.cpu.toFixed(1)} %`;
    document.getElementById('memory-usage').innerText = `${sys_info.memory.toFixed(1)} %`;
    document.getElementById('disk-usage').innerText = `${sys_info.disk.toFixed(1)} %`;
}

/**
 * 更新流量统计表格
 * @param {Array} stats - 流量统计数据数组
 */
function updateStatsTable(stats) {
    const statsTableBody = document.getElementById('stats-table-body');
    if (stats && stats.length > 0) {
        statsTableBody.innerHTML = stats.map(stat => 
            `<tr>
                <td><code>${stat.name}</code></td>
                <td class="text-end"><span class="badge bg-primary rounded-pill fs-6">${stat.value}</span></td>
            </tr>`
        ).join('');
    } else {
        statsTableBody.innerHTML = '<tr><td colspan="2">暂无流量数据</td></tr>';
    }
}

/**
 * 更新IP管控状态列表（封禁/限速）
 * @param {Array} banned_ips - 已封禁IP列表
 * @param {Array} limited_ips - 已限速IP列表
 */
function updateIpControlLists(banned_ips, limited_ips) {
    const bannedList = document.getElementById('banned-ips-list');
    const limitedList = document.getElementById('limited-ips-list');

    bannedList.innerHTML = banned_ips.map(item => 
        `<li class="list-group-item d-flex justify-content-between align-items-center">
            <code>${item.ip}</code>
            <button class="btn btn-success btn-sm btn-action" data-action="unban-ip" data-value="${item.num}" data-ip="${item.ip}">手动解封</button>
        </li>`
    ).join('') || '<li class="list-group-item">当前没有手动封禁的 IP。</li>';
    
    limitedList.innerHTML = limited_ips.map(item => 
        `<li class="list-group-item d-flex justify-content-between align-items-center">
            <code>${item.ip}</code>
            <span class="badge bg-info">${item.rate}</span>
            <button class="btn btn-outline-secondary btn-sm btn-action" data-action="remove-ip-limit" data-value="${item.ip}">取消</button>
        </li>`
    ).join('') || '<li class="list-group-item">当前没有已限速的 IP。</li>';
}

/**
 * 更新近期连接记录的折叠菜单
 * @param {object} connections - 按IP分组的连接数据
 * @param {Array} banned_ips - 已封禁IP列表
 * @param {Array} limited_ips - 已限速IP列表
 */
function updateConnectionsAccordion(connections, banned_ips, limited_ips) {
    const accordion = document.getElementById('connectionsAccordion');
    const bannedIpMap = new Map(banned_ips.map(item => [item.ip, item.num]));
    const limitedIpMap = new Map(limited_ips.map(item => [item.ip, item.rate]));

    if (connections && Object.keys(connections).length > 0) {
        accordion.innerHTML = Object.entries(connections).map(([ip, conn_list], index) => {
            const locationInfo = conn_list[0].location ? `<small class="text-muted ms-2">(${conn_list[0].location})</small>` : '';
            
            const detailsHtml = conn_list.slice(0, 100).reverse().map(conn => {
                const reputation = conn.reputation || { status: 'N/A', class: 'light' };
                return `<tr>
                            <td><small>${conn.timestamp}</small></td>
                            <td>
                                <code>${conn.destination}</code>
                                <span class="badge bg-${reputation.class} float-end">${reputation.status}</span>
                            </td>
                        </tr>`;
            }).join('');
            
            let ipStatusHtml = '';
            if (bannedIpMap.has(ip)) {
                ipStatusHtml = `<button class="btn btn-success btn-sm btn-action" data-action="unban-ip" data-value="${bannedIpMap.get(ip)}" data-ip="${ip}">解封</button>`;
            } else if (limitedIpMap.has(ip)) {
                const rate = limitedIpMap.get(ip);
                ipStatusHtml = `<span class="badge bg-info me-2">${rate}</span><button class="btn btn-outline-secondary btn-sm btn-action" data-action="remove-ip-limit" data-value="${ip}">取消限速</button>`;
            } else {
                ipStatusHtml = `
                    <button class="btn btn-danger btn-sm btn-action me-1" data-action="ban-ip" data-value="${ip}">封禁</button>
                    <button class="btn btn-primary btn-sm btn-action" data-action="limit-ip" data-value="${ip}">限速</button>`;
            }

            return `<div class="accordion-item">
                        <h2 class="accordion-header">
                            <button class="accordion-button collapsed fw-bold" type="button" data-bs-toggle="collapse" data-bs-target="#collapse-${index}">
                                来源 IP: <code>${ip}</code> ${locationInfo}
                                <span class="badge bg-secondary ms-auto me-2">连接数: ${conn_list.length}</span>
                                ${ipStatusHtml}
                            </button>
                        </h2>
                        <div id="collapse-${index}" class="accordion-collapse collapse" data-bs-parent="#connectionsAccordion">
                            <div class="accordion-body p-2"><table class="table table-sm table-striped table-hover mb-0"><thead><tr><th>时间戳</th><th>访问目标 (信誉)</th></tr></thead><tbody>${detailsHtml}</tbody></table></div>
                        </div>
                    </div>`;
        }).join('');
    } else {
        accordion.innerHTML = '<p class="text-center text-muted">暂无近期连接记录</p>';
    }
}

/**
 * 更新连接数来源分布的饼图
 * @param {object} connections - 按IP分组的连接数据
 */
function updateConnectionsChart(connections) {
    if (connections && Object.keys(connections).length > 0) {
        const chart_labels = Object.keys(connections);
        const chart_data = Object.values(connections).map(v => v.length);
        
        if (connectionsChart) {
            connectionsChart.data.labels = chart_labels;
            connectionsChart.data.datasets[0].data = chart_data;
            connectionsChart.update();
        } else {
            const ctx = document.getElementById('connectionsChart').getContext('2d');
            connectionsChart = new Chart(ctx, { 
                type: 'pie', 
                data: { 
                    labels: chart_labels, 
                    datasets: [{ 
                        data: chart_data, 
                        borderWidth: 1,
                        backgroundColor: [
                            'rgba(255, 99, 132, 0.7)', 'rgba(54, 162, 235, 0.7)',
                            'rgba(255, 206, 86, 0.7)', 'rgba(75, 192, 192, 0.7)',
                            'rgba(153, 102, 255, 0.7)','rgba(255, 159, 64, 0.7)'
                        ]
                    }] 
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'top',
                        }
                    }
                }
            });
        }
    }
}

/**
 * 统一的事件处理函数，用于处理所有控制按钮的点击
 * @param {Event} event - 点击事件对象
 */
function handleActionClick(event) {
    const target = event.target.closest('.btn-action');
    if (!target) return;
    event.preventDefault();

    const action = target.dataset.action;
    const value = target.dataset.value;
    const ip = target.dataset.ip; // 用于解封时传递IP
    let confirmMsg = '', url = '', showConfirm = true;

    switch(action) {
        case 'restart-xray': url = '/actions/restart_xray'; confirmMsg = '您确定要重启 Xray 服务吗？'; break;
        case 'ban-ip': url = `/actions/ban/${value}`; confirmMsg = `您确定要封禁 IP 地址 <strong>${value}</strong> 吗？`; break;
        case 'unban-ip': url = `/actions/unban/${value}/${ip}`; confirmMsg = `您确定要解封 IP <strong>${ip}</strong> (规则 #${value}) 吗？`; break;
        case 'remove-ip-limit': url = `/actions/remove_ip_limit`; confirmMsg = `您确定要取消对 IP <strong>${value}</strong> 的限速吗？`; break;
        case 'limit-ip': 
            showConfirm = false;
            document.getElementById('limitIpAddress').innerText = value;
            limitIpModal.show();
            document.getElementById('confirmLimitButton').onclick = () => {
                const rate = document.getElementById('limitRateInput').value;
                const formData = new FormData();
                formData.append('ip', value);
                formData.append('rate_kbit', rate);
                performAction('/actions/set_ip_limit', { method: 'POST', body: formData });
                limitIpModal.hide();
            };
            break;
    }
    
    if (showConfirm && url) {
        const modalBody = document.getElementById('confirmModalBody');
        const confirmButton = document.getElementById('confirmModalButton');
        modalBody.innerHTML = confirmMsg;
        confirmModal.show();
        
        let postBody = null;
        if (action === 'remove-ip-limit') {
            const formData = new FormData();
            formData.append('ip', value);
            postBody = formData;
        }

        confirmButton.onclick = () => { performAction(url, { method: 'POST', body: postBody }); confirmModal.hide(); };
    }
}

/**
 * 异步函数，用于向后端发送控制请求
 * @param {string} url - 请求的URL
 * @param {object} options - fetch API 的选项
 */
async function performAction(url, options) {
    try {
        const response = await fetch(url, options);
        const result = await response.json();
        alert(result.message);
        if (response.ok) {
            updateDashboard(); // 操作成功后立即刷新数据
        }
    } catch (error) {
        alert('操作失败，请查看浏览器控制台日志。');
        console.error('Action failed:', error);
    }
}

// --- 主程序入口 ---
document.addEventListener('DOMContentLoaded', () => {
    // 初始化模态框实例
    confirmModal = new bootstrap.Modal(document.getElementById('confirmModal'));
    limitIpModal = new bootstrap.Modal(document.getElementById('limitIpModal'));

    // 绑定全局点击事件监听器
    document.body.addEventListener('click', handleActionClick);

    // 页面加载时立即执行一次数据更新，然后每 15 秒刷新一次
    updateDashboard();
    setInterval(updateDashboard, 15000);
});
