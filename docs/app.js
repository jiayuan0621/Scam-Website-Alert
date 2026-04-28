const KNOWN_PHISHING_DOMAINS = [
    'fake-login', 'phishing', 'scam', 'suspicious',
    'secure-bank', 'account-verify', 'password-reset',
    'login-verify', 'security-check', 'unusual-login',
    'suspended-account', 'confirm-identity', 'urgent-action',
    'free-gift', 'winner', 'lottery', 'prize-claim',
    'bit.ly', 'tinyurl', 't.co', 'goo.gl', 'ow.ly',
    'is.gd', 'buff.ly', 'adf.ly', 'j.mp'
];

const SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'verify', 'secure', 'account', 'password',
    'banking', 'payment', 'confirm', 'update', 'alert', 'urgent',
    'suspended', 'unusual', 'suspicious', 'security', 'private',
    'personal', 'identity', 'ssn', 'credit', 'social', 'insurance',
    'lottery', 'winner', 'prize', 'gift', 'free', 'claim',
    'bitcoin', 'crypto', 'wallet', 'ethereum', 'btc'
];

const SUSPICIOUS_TLDS = [
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', 
    '.work', '.click', '.link', '.buzz', '.stream', '.date',
    '.win', '.review', '.country', '.stream', '.download',
    '.trade', '.accountant', '.cricket', '.racing'
];

const LEGITIMATE_TLDS = [
    '.com', '.org', '.net', '.edu', '.gov', '.io', '.co',
    '.us', '.uk', '.de', '.fr', '.jp', '.cn', '.au', '.ca'
];

class PhishingDetector {
    constructor() {
        this.history = [];
        this.init();
    }

    init() {
        const savedHistory = localStorage.getItem('detectionHistory');
        if (savedHistory) {
            this.history = JSON.parse(savedHistory);
            this.renderHistory();
        }

        document.getElementById('scanBtn').addEventListener('click', () => this.scan());
        document.getElementById('urlInput').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.scan();
        });
    }

    parseUrl(url) {
        try {
            let urlToParse = url.trim();
            
            if (!urlToParse.startsWith('http://') && !urlToParse.startsWith('https://')) {
                urlToParse = 'https://' + urlToParse;
            }
            
            const parsed = new URL(urlToParse);
            return {
                valid: true,
                fullUrl: urlToParse,
                protocol: parsed.protocol.replace(':', ''),
                hostname: parsed.hostname,
                port: parsed.port || (parsed.protocol === 'https:' ? '443' : '80'),
                pathname: parsed.pathname || '/',
                search: parsed.search || '',
                hash: parsed.hash || '',
                tld: this.extractTLD(parsed.hostname),
                domain: this.extractDomain(parsed.hostname),
                subdomain: this.extractSubdomain(parsed.hostname),
                pathSegments: this.getPathSegments(parsed.pathname),
                queryParams: this.parseQueryParams(parsed.search),
                isIp: this.isIpAddress(parsed.hostname),
                hasSuspiciousPort: this.checkSuspiciousPort(parsed.port),
                urlLength: urlToParse.length,
                pathLength: parsed.pathname.length
            };
        } catch (e) {
            return { valid: false, error: e.message };
        }
    }

    extractTLD(hostname) {
        const parts = hostname.split('.');
        if (parts.length >= 2) {
            return '.' + parts.slice(-2).join('.');
        }
        return '.' + hostname;
    }

    extractDomain(hostname) {
        const parts = hostname.split('.');
        if (parts.length >= 2) {
            return parts.slice(-2).join('.');
        }
        return hostname;
    }

    extractSubdomain(hostname) {
        const parts = hostname.split('.');
        if (parts.length > 2) {
            return parts.slice(0, -2).join('.');
        }
        return '';
    }

    getPathSegments(pathname) {
        return pathname.split('/').filter(seg => seg.length > 0);
    }

    parseQueryParams(search) {
        if (!search) return {};
        const params = {};
        search.substring(1).split('&').forEach(pair => {
            const [key, value] = pair.split('=');
            if (key) params[decodeURIComponent(key)] = decodeURIComponent(value || '');
        });
        return params;
    }

    isIpAddress(hostname) {
        const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
        return ipPattern.test(hostname);
    }

    checkSuspiciousPort(port) {
        const suspiciousPorts = ['8080', '8443', '4444', '5555', '6666', '7777', '8888', '9999'];
        return suspiciousPorts.includes(port);
    }

    checkBlacklist(domain, hostname) {
        const lowerDomain = domain.toLowerCase();
        const lowerHostname = hostname.toLowerCase();

        for (const blocked of KNOWN_PHISHING_DOMAINS) {
            if (lowerHostname.includes(blocked)) {
                return { blocked: true, reason: `包含可疑域名关键词: ${blocked}` };
            }
        }

        const popularBrands = ['apple', 'microsoft', 'google', 'amazon', 'paypal', 'facebook', 'twitter', 'netflix', 'ebay', 'whatsapp'];
        for (const brand of popularBrands) {
            if (lowerDomain.includes(brand) && !lowerDomain.endsWith(brand + '.com') && !lowerDomain.endsWith(brand + '.org')) {
                return { blocked: true, reason: `疑似冒充知名品牌的域名: ${brand}` };
            }
        }

        return { blocked: false };
    }

    analyzeSuspiciousPatterns(parsedUrl) {
        const checks = [];
        const hostname = parsedUrl.hostname.toLowerCase();
        const pathname = parsedUrl.pathname.toLowerCase();

        if (parsedUrl.isIp) {
            checks.push({
                name: '使用IP地址而非域名',
                status: 'warning',
                detail: '正规网站通常使用域名而非IP地址'
            });
        }

        if (parsedUrl.urlLength > 200) {
            checks.push({
                name: 'URL长度异常',
                status: 'warning',
                detail: '过长的URL可能隐藏真实目的地'
            });
        }

        if (parsedUrl.hasSuspiciousPort) {
            checks.push({
                name: '使用可疑端口',
                status: 'warning',
                detail: `端口 ${parsedUrl.port} 常被用于钓鱼网站`
            });
        }

        if (parsedUrl.subdomain) {
            const subdomains = parsedUrl.subdomain.toLowerCase().split('.');
            for (const sub of subdomains) {
                if (SUSPICIOUS_KEYWORDS.some(kw => sub.includes(kw))) {
                    checks.push({
                        name: '子域名包含可疑关键词',
                        status: 'warning',
                        detail: `子域名 "${parsedUrl.subdomain}" 包含可疑词汇`
                    });
                    break;
                }
            }
        }

        const pathLower = pathname + parsedUrl.search;
        for (const keyword of SUSPICIOUS_KEYWORDS) {
            if (pathLower.includes(keyword)) {
                const suspiciousInPath = parsedUrl.pathSegments.some(seg => 
                    seg.length > 15 || /\d{5,}/.test(seg) || /[_-]{2,}/.test(seg)
                );
                if (suspiciousInPath) {
                    checks.push({
                        name: '路径包含可疑关键词和异常字符',
                        status: 'warning',
                        detail: `路径可能试图混淆真实意图`
                    });
                    break;
                }
            }
        }

        if (parsedUrl.hash && parsedUrl.hash.length > 5) {
            checks.push({
                name: 'URL包含可疑锚点',
                status: 'warning',
                detail: '锚点可能用于重定向到恶意页面'
            });
        }

        const hasSuspiciousTld = SUSPICIOUS_TLDS.some(tld => parsedUrl.tld === tld || hostname.endsWith(tld));
        if (hasSuspiciousTld) {
            checks.push({
                name: '使用高风险顶级域名',
                status: 'warning',
                detail: `TLD ${parsedUrl.tld} 常被用于钓鱼网站`
            });
        }

        if (parsedUrl.search) {
            const sensitiveParams = ['redirect', 'url', 'link', 'goto', 'next', 'return', 'token', 'auth'];
            const paramKeys = Object.keys(parsedUrl.queryParams);
            for (const param of sensitiveParams) {
                if (paramKeys.some(k => k.toLowerCase().includes(param))) {
                    checks.push({
                        name: '包含可疑查询参数',
                        status: 'warning',
                        detail: `参数 "${param}" 可能用于重定向到恶意网站`
                    });
                    break;
                }
            }
        }

        return checks;
    }

    calculateRiskScore(parsedUrl, blacklistResult, patternChecks) {
        let score = 0;

        if (blacklistResult.blocked) {
            score += 50;
        }

        const hostname = parsedUrl.hostname.toLowerCase();
        const popularBrands = ['apple', 'microsoft', 'google', 'amazon', 'paypal', 'facebook', 'twitter', 'netflix', 'ebay', 'whatsapp', 'linkedin', 'instagram'];
        const isBrandImpersonation = popularBrands.some(brand => 
            hostname.includes(brand) && 
            !hostname.endsWith(brand + '.com') && 
            !hostname.endsWith(brand + '.org') &&
            !hostname.endsWith(brand + '.net')
        );
        if (isBrandImpersonation) {
            score += 25;
        }

        if (parsedUrl.isIp) score += 15;
        if (parsedUrl.urlLength > 200) score += 10;
        if (parsedUrl.urlLength > 500) score += 15;
        if (parsedUrl.hasSuspiciousPort) score += 15;

        const hasSuspiciousTld = SUSPICIOUS_TLDS.some(tld => parsedUrl.tld === tld || hostname.endsWith(tld));
        if (hasSuspiciousTld) score += 20;

        patternChecks.forEach(check => {
            if (check.status === 'warning') score += 8;
            if (check.status === 'fail') score += 15;
        });

        const suspiciousCount = patternChecks.filter(c => c.status === 'warning' || c.status === 'fail').length;
        if (suspiciousCount >= 5) score += 10;

        if (parsedUrl.search) {
            const redirectParams = ['redirect', 'url', 'link', 'goto', 'next', 'return'];
            const paramKeys = Object.keys(parsedUrl.queryParams);
            if (paramKeys.some(k => redirectParams.includes(k.toLowerCase()))) {
                score += 10;
            }
        }

        return Math.min(score, 100);
    }

    getRiskLevel(score) {
        if (score >= 70) return { level: 'critical', label: '极度危险', color: '#dc2626' };
        if (score >= 50) return { level: 'high', label: '高风险', color: '#ef4444' };
        if (score >= 30) return { level: 'medium', label: '中等风险', color: '#f97316' };
        if (score >= 15) return { level: 'low', label: '低风险', color: '#f59e0b' };
        return { level: 'safe', label: '相对安全', color: '#10b981' };
    }

    getRecommendation(parsedUrl, riskInfo) {
        if (riskInfo.level === 'critical') {
            return {
                type: 'danger',
                text: '🚨 强烈建议不要访问此链接！该网站极有可能是钓鱼网站，可能会导致您的账号被盗、财产损失或个人信息泄露。建议立即删除并不要在任何设备上打开。'
            };
        }
        if (riskInfo.level === 'high') {
            return {
                type: 'danger',
                text: '⚠️ 建议谨慎处理此链接。该网站存在较多可疑特征，请确认来源是否可靠，切勿输入任何个人敏感信息。'
            };
        }
        if (riskInfo.level === 'medium') {
            return {
                type: 'warning',
                text: '⚡ 此链接存在一定风险。建议进一步核实链接来源后再决定是否访问。避免输入账号密码等敏感信息。'
            };
        }
        if (riskInfo.level === 'low') {
            return {
                type: 'info',
                text: 'ℹ️ 该链接暂时未发现明显风险，但仍建议保持警惕，特别是不要在不确认的网站输入个人信息。'
            };
        }
        return {
            type: 'safe',
            text: '✅ 该链接暂未发现明显威胁特征，但网络钓鱼手法不断演变，请始终保持警惕。'
        };
    }

    async scan() {
        const input = document.getElementById('urlInput');
        const url = input.value.trim();
        
        if (!url) {
            alert('请输入要检测的链接');
            return;
        }

        document.getElementById('loading').classList.remove('hidden');
        document.getElementById('results').classList.add('hidden');

        await new Promise(resolve => setTimeout(resolve, 800));

        const parsed = this.parseUrl(url);

        if (!parsed.valid) {
            document.getElementById('loading').classList.add('hidden');
            alert('无效的URL格式，请检查输入的链接');
            return;
        }

        const blacklistResult = this.checkBlacklist(parsed.domain, parsed.hostname);
        const patternChecks = this.analyzeSuspiciousPatterns(parsed);
        const riskScore = this.calculateRiskScore(parsed, blacklistResult, patternChecks);
        const riskInfo = this.getRiskLevel(riskScore);
        const recommendation = this.getRecommendation(parsed, riskInfo);

        const result = {
            url: parsed.fullUrl,
            parsed,
            blacklistResult,
            patternChecks,
            riskScore,
            riskInfo,
            recommendation,
            timestamp: new Date().toISOString()
        };

        this.history.unshift(result);
        if (this.history.length > 10) {
            this.history = this.history.slice(0, 10);
        }
        localStorage.setItem('detectionHistory', JSON.stringify(this.history));

        this.displayResults(result);
        this.renderHistory();

        document.getElementById('loading').classList.add('hidden');
        document.getElementById('results').classList.remove('hidden');
    }

    displayResults(result) {
        const { parsed, blacklistResult, patternChecks, riskScore, riskInfo, recommendation } = result;

        const badge = document.getElementById('riskBadge');
        badge.textContent = this.getRiskEmoji(riskInfo.level);
        badge.className = 'risk-badge ' + riskInfo.level;
        
        document.getElementById('riskLevel').textContent = riskInfo.label;

        const scoreCircle = document.getElementById('scoreCircle');
        scoreCircle.style.setProperty('--score', riskScore);
        scoreCircle.style.setProperty('--score-color', riskInfo.color);
        document.getElementById('scoreValue').textContent = riskScore;

        const warningEl = document.getElementById('warningMessage');
        if (blacklistResult.blocked) {
            warningEl.textContent = '⚠️ ' + blacklistResult.reason;
            warningEl.className = 'warning-message danger';
        } else {
            warningEl.classList.add('hidden');
        }

        const urlDetails = document.getElementById('urlDetails');
        urlDetails.innerHTML = `
            <div class="detail-item">
                <div class="label">完整URL</div>
                <div class="value">${this.escapeHtml(parsed.fullUrl)}</div>
            </div>
            <div class="detail-item">
                <div class="label">协议</div>
                <div class="value ${parsed.protocol === 'https' ? '' : 'suspicious'}">${parsed.protocol.toUpperCase()}</div>
            </div>
            <div class="detail-item">
                <div class="label">域名</div>
                <div class="value ${blacklistResult.blocked ? 'danger' : ''}">${this.escapeHtml(parsed.hostname)}</div>
            </div>
            <div class="detail-item">
                <div class="label">顶级域名</div>
                <div class="value ${SUSPICIOUS_TLDS.some(t => parsed.tld === t) ? 'suspicious' : ''}">${parsed.tld}</div>
            </div>
            <div class="detail-item">
                <div class="label">路径</div>
                <div class="value">${parsed.pathname === '/' ? '/' : this.escapeHtml(parsed.pathname)}</div>
            </div>
            <div class="detail-item">
                <div class="label">URL长度</div>
                <div class="value ${parsed.urlLength > 200 ? 'suspicious' : ''}">${parsed.urlLength} 字符</div>
            </div>
        `;

        const checkDetails = document.getElementById('checkDetails');
        checkDetails.innerHTML = '';

        if (patternChecks.length === 0) {
            checkDetails.innerHTML += `
                <div class="check-item">
                    <span class="icon pass">✓</span>
                    <span class="text">未发现明显可疑特征</span>
                    <span class="status pass">通过</span>
                </div>
            `;
        } else {
            patternChecks.forEach(check => {
                checkDetails.innerHTML += `
                    <div class="check-item">
                        <span class="icon ${check.status}">${check.status === 'warning' ? '⚠' : '✗'}</span>
                        <span class="text">${check.name}<br><small style="color:#64748b">${check.detail}</small></span>
                        <span class="status ${check.status}">${check.status === 'warning' ? '警告' : '危险'}</span>
                    </div>
                `;
            });
        }

        const recEl = document.getElementById('recommendation');
        recEl.textContent = recommendation.text;
        recEl.className = 'recommendation ' + recommendation.type;
        recEl.classList.remove('hidden');
    }

    getRiskEmoji(level) {
        const emojis = {
            safe: '✅',
            low: '⚡',
            medium: '⚠️',
            high: '🚨',
            critical: '☠️'
        };
        return emojis[level] || '❓';
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    renderHistory() {
        const historyList = document.getElementById('historyList');
        
        if (this.history.length === 0) {
            historyList.innerHTML = '<div class="empty-history">暂无检测历史</div>';
            return;
        }

        historyList.innerHTML = this.history.map((item, index) => {
            const shortUrl = item.parsed.hostname + (item.parsed.pathname !== '/' ? item.parsed.pathname : '');
            const truncatedUrl = shortUrl.length > 40 ? shortUrl.substring(0, 40) + '...' : shortUrl;
            
            return `
                <div class="history-item" data-index="${index}">
                    <span class="url" title="${this.escapeHtml(item.url)}">${this.escapeHtml(truncatedUrl)}</span>
                    <span class="mini-badge ${item.riskInfo.level}">${item.riskScore}分</span>
                </div>
            `;
        }).join('');

        historyList.querySelectorAll('.history-item').forEach(item => {
            item.addEventListener('click', () => {
                const index = parseInt(item.dataset.index);
                const result = this.history[index];
                this.displayResults(result);
                document.getElementById('results').classList.remove('hidden');
                document.getElementById('urlInput').value = result.url;
                document.getElementById('loading').classList.add('hidden');
            });
        });
    }
}

document.addEventListener('DOMContentLoaded', () => {
    new PhishingDetector();
});