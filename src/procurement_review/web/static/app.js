/**
 * procurement_review 本機前端腳本
 *
 * 保證：
 * 1. 注音／中文輸入法 Composition 保護：isComposing 期間按 Enter 不觸發表單送出。
 * 2. URL Fragment Bootstrap 交換：啟動 token 交換 HttpOnly cookie，隨即清除 fragment，不留存於歷史紀錄。
 * 3. 變更性 API 請求自動附帶 X-CSRF-Token。
 * 4. 表單變更未存警示。
 */

let _csrfToken = '';
let _isFormDirty = false;

// 1. 初始化 Bootstrap Token 交換
window.addEventListener('DOMContentLoaded', async () => {
    // 檢查 URL fragment
    const hash = window.location.hash;
    if (hash && hash.includes('token=')) {
        const params = new URLSearchParams(hash.substring(1));
        const token = params.get('token');
        if (token) {
            try {
                const res = await fetch('/api/auth/bootstrap', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ token: token })
                });
                if (res.ok) {
                    const data = await res.json();
                    _csrfToken = data.csrf_token;
                    // 清除 fragment 避免外洩
                    history.replaceState(null, '', window.location.pathname + window.location.search);
                    window.location.reload();
                    return;
                }
            } catch (err) {
                console.error('Bootstrap exchange error:', err);
            }
        }
    }

    // 取得目前會話之 CSRF Token
    try {
        const res = await fetch('/api/auth/me');
        if (res.ok) {
            const data = await res.json();
            _csrfToken = data.csrf_token;
            const opEl = document.getElementById('operator-badge');
            if (opEl && data.operator) {
                opEl.textContent = data.operator;
            }
        }
    } catch (e) {
        // 未登入或尚未交換會話
    }

    // 2. 表單變更未存提醒
    document.querySelectorAll('form, input, textarea, select').forEach(el => {
        el.addEventListener('input', () => {
            _isFormDirty = true;
        });
    });

    window.addEventListener('beforeunload', (e) => {
        if (_isFormDirty) {
            e.preventDefault();
            e.returnValue = '您有尚未儲存的變更，確定要離開嗎？';
            return e.returnValue;
        }
    });

    // 3. 注音 / 中文輸入法 Composition 防護 (Enter 鍵不誤送出)
    window.isComposing = false;
    window.addEventListener('compositionstart', () => { window.isComposing = true; });
    window.addEventListener('compositionend', () => { window.isComposing = false; });

    document.addEventListener('keydown', (e) => {
        const isComposing = Boolean(e.isComposing || window.isComposing || e.keyCode === 229);
        if (isComposing && (e.key === 'Enter' || e.keyCode === 13 || e.keyCode === 229)) {
            // 中文輸入法選字中，同時阻擋預設送出行為與事件向上冒泡
            e.stopPropagation();
            e.preventDefault();
        }
    }, true);
});

// 任務輪詢輔助工具
async function pollTask(taskId, options = {}) {
    const interval = options.interval || 500;
    const onProgress = options.onProgress || (() => {});
    return new Promise((resolve, reject) => {
        const timer = setInterval(async () => {
            try {
                const task = await apiRequest(`/api/tasks/${taskId}`);
                onProgress(task);
                if (task.status === 'completed') {
                    clearInterval(timer);
                    resolve(task);
                } else if (task.status === 'failed') {
                    clearInterval(timer);
                    reject(new Error(task.error || task.message || 'Task failed'));
                }
            } catch (err) {
                clearInterval(timer);
                reject(err);
            }
        }, interval);
    });
}

// 通用 Fetch 封裝，自動注入 CSRF Token
async function apiRequest(url, options = {}) {
    options.headers = options.headers || {};
    if (options.method && ['POST', 'PUT', 'DELETE', 'PATCH'].includes(options.method.toUpperCase())) {
        if (_csrfToken) {
            options.headers['X-CSRF-Token'] = _csrfToken;
        }
    }
    const res = await fetch(url, options);
    if (!res.ok) {
        let msg = `HTTP ${res.status}`;
        try {
            const err = await res.json();
            msg = err.detail || msg;
        } catch (_) {}
        throw new Error(msg);
    }
    return await res.json();
}

